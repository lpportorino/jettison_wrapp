package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/pelletier/go-toml"
	"github.com/redis/go-redis/v9"
)

const (
    streamSuffixInfo   = ":info"
    streamSuffixStatus = ":status"
    streamSuffixError  = ":error"
    streamSuffixCrash  = ":crash"
)

var ctx = context.Background()

type Config struct {
	// Redis configuration
	Redis struct {
		Host     string `toml:"host"`
		Password string `toml:"password"`
		Port     int    `toml:"port"`
	} `toml:"redis"`

	// Application configuration
	App struct {
		Executable string   `toml:"executable"`
		Args       []string `toml:"args"`
		User       string   `toml:"user"`
		StreamName string   `toml:"stream_name"`
	} `toml:"app"`
}

type RedisLogger struct {
	configClient, logClient, valueClient *redis.Client
	multiLineBuffer                      *strings.Builder
	bufferMutex                          sync.Mutex
	maxBufferSize                        int
	streamName                           string
}

func main() {
    if len(os.Args) != 2 {
        fmt.Fprintf(os.Stderr, "Usage: wrapp <path_to_toml>\n")
        os.Exit(1)
    }

    tomlPath := os.Args[1]
    debugPrintf("Loading configuration from: %s", tomlPath)

    config, err := loadConfig(tomlPath)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error loading configuration: %v\n", err)
        os.Exit(1)
    }

    debugPrintf("Config loaded - Executable: %s, Args: %v, User: %s, Stream: %s",
        config.App.Executable, config.App.Args, config.App.User, config.App.StreamName)
    debugPrintf("Redis connection: %s:%d", config.Redis.Host, config.Redis.Port)

    logger := NewRedisLogger(config)
    defer logger.Close()

    if err := setupRedisConnection(logger.configClient); err != nil {
        fmt.Fprintf(os.Stderr, "Redis setup error: %v\n", err)
        os.Exit(1)
    }

    go continuouslyPingRedis(logger.logClient, time.Second * 60)
    go continuouslyPingRedis(logger.valueClient, time.Second * 60)

    absExecutable, err := resolveExecutablePath(config.App.Executable)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error resolving executable path: %v\n", err)
        os.Exit(1)
    }
    debugPrintf("Resolved executable path: %s", absExecutable)

    // Determine target user
    targetUser := determineUser(config.App.User)
    debugPrintf("Process will run as user: %s", targetUser)

    if err := runExecutableAndLog(targetUser, absExecutable, config.App.Args, logger); err != nil {
        fmt.Fprintf(os.Stderr, "Error running executable: %v\n", err)
        os.Exit(1)
    }
}

func determineUser(configUser string) string {
	// If running as root and user is specified in config, use it
	if os.Geteuid() == 0 && configUser != "" {
		debugPrintf("Running as root, switching to configured user: %s", configUser)
		return configUser
	}
	// If running as root but no user specified, default to "archer"
	if os.Geteuid() == 0 {
		debugPrintln("Running as root with no user specified, defaulting to 'archer'")
		return "archer"
	}
	// If not root, use current user regardless of config
	currentUser, _ := user.Current()
	debugPrintf("Not running as root, using current user: %s", currentUser.Username)
	return currentUser.Username
}

func setupRedisConnection(client *redis.Client) error {
	if err := tryRedisConnection(client); err != nil {
		return waitRedisToBecomeAvailable(client, 60*time.Second, 5*time.Second)
	}
	return nil
}

func resolveExecutablePath(executable string) (string, error) {
	resolvedExecutable, err := exec.LookPath(executable)
	if err != nil {
		return "", fmt.Errorf("error resolving executable path: %w", err)
	}
	return filepath.Abs(resolvedExecutable)
}

func tryRedisConnection(rdb *redis.Client) error {
	_, err := rdb.Ping(ctx).Result()
	if err != nil {
		debugPrintf("Redis ping failed: %v", err)
		fmt.Println("Initial Redis connection failed, will wait for Redis to become available...")
		return err
	}
	debugPrintln("Redis ping successful")
	fmt.Println("Connected to Redis.")
	return nil
}

func loadConfig(tomlPath string) (*Config, error) {
	var config Config
	configData, err := toml.LoadFile(tomlPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load TOML config file: %w", err)
	}

	if err := configData.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// Set default stream name if not specified
	if config.App.StreamName == "" {
		// Use executable base name as default
		config.App.StreamName = filepath.Base(config.App.Executable)
		debugPrintf("No stream_name specified, using executable base name: %s", config.App.StreamName)
	}

	return &config, nil
}

func newRedisClient(config *Config, db int) *redis.Client {
	return redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%d", config.Redis.Host, config.Redis.Port),
		Password: config.Redis.Password,
		DB:       db,
	})
}

func waitRedisToBecomeAvailable(rdb *redis.Client, timeout, checkInterval time.Duration) error {
	timeoutChan := time.After(timeout)
	ticker := time.NewTicker(checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-timeoutChan:
			return fmt.Errorf("timeout waiting for Redis to become available")
		case <-ticker.C:
			if _, err := rdb.Ping(ctx).Result(); err == nil {
				fmt.Println("Redis is available.")
				return nil
			}
			fmt.Println("Waiting for Redis to become available...")
		}
	}
}

func NewRedisLogger(config *Config) *RedisLogger {
	return &RedisLogger{
		configClient:  newRedisClient(config, 5),
		logClient:     newRedisClient(config, 1),
		valueClient:   newRedisClient(config, 2),
		maxBufferSize: 1024 * 1024 * 10,
		streamName:    config.App.StreamName,
	}
}

func (rl *RedisLogger) Close() {
	rl.configClient.Close()
	rl.logClient.Close()
	rl.valueClient.Close()
}

func setupCoreDumpHandler(executable string, logger *RedisLogger, infoKey string) {
	out, err := exec.Command("sh", "-c", "ulimit -c").Output()
	if err != nil {
		logger.logMessage(infoKey, fmt.Sprintf("Error checking core dump limits: %v", err), "error")
		return
	}

	if strings.TrimSpace(string(out)) == "0" {
		logger.logMessage(infoKey, "Core dumps are disabled. Please run the setup script as root.", "error")
		return
	}

	// Core pattern configured in system_config.sh as: /tmp/core-%E-%t-%p-%s
	// %E = full path with slashes replaced by exclamation marks
	// %t = timestamp (seconds since epoch)
	// %p = process ID
	// %s = signal number that caused the dump
	// Example: /tmp/core-!usr!bin!myapp-1734567890-12345-11
	logger.logMessage(infoKey, fmt.Sprintf("Core dump handling is set up. Pattern uses full path: %s", executable), "status")
}

func cleanupPreviousCoreDumps(executable string, logger *RedisLogger, infoKey string) error {
	// Match kernel pattern: /tmp/core-%E-%t-%p-%s
	// %E replaces slashes with exclamation marks
	executableSafe := strings.ReplaceAll(executable, "/", "!")
	corePattern := fmt.Sprintf("/tmp/core-%s-*", executableSafe)
	files, err := filepath.Glob(corePattern)
	if err != nil {
		logger.logMessage(infoKey, fmt.Sprintf("Error checking for previous core dumps: %v", err), "error")
		return err
	}

	for _, file := range files {
		if err := os.Remove(file); err != nil {
			logger.logMessage(infoKey, fmt.Sprintf("Error removing previous core dump %s: %v", file, err), "error")
		} else {
			logger.logMessage(infoKey, fmt.Sprintf("Removed previous core dump: %s", file), "status")
		}
	}

	return nil
}

func checkForCoreDumps(executable string, logger *RedisLogger, infoKey string, processStartTime time.Time) {
	// Match kernel pattern: /tmp/core-%E-%t-%p-%s
	// %E replaces slashes with exclamation marks
	executableSafe := strings.ReplaceAll(executable, "/", "!")
	corePattern := fmt.Sprintf("/tmp/core-%s-*", executableSafe)
	files, err := filepath.Glob(corePattern)
	if err != nil {
		logger.logMessage(infoKey, fmt.Sprintf("Error checking for core dumps: %v", err), "error")
		return
	}

	if len(files) == 0 {
		return
	}

	// Filter files to only those created after process start
	var newCoreDumps []string
	for _, file := range files {
		info, err := os.Stat(file)
		if err != nil {
			continue
		}
		// Check if the file was created after the process started
		// Using a 1-second buffer before start time to account for clock skew
		if info.ModTime().After(processStartTime.Add(-1 * time.Second)) {
			newCoreDumps = append(newCoreDumps, file)
		}
	}

	if len(newCoreDumps) == 0 {
		return
	}

	// Sort by modification time, newest first
	sort.Slice(newCoreDumps, func(i, j int) bool {
		iInfo, _ := os.Stat(newCoreDumps[i])
		jInfo, _ := os.Stat(newCoreDumps[j])
		return iInfo.ModTime().After(jInfo.ModTime())
	})

	logger.logMessage(infoKey, fmt.Sprintf("Found %d new core dump(s) for analysis", len(newCoreDumps)), "status")

	for _, coreDump := range newCoreDumps {
		analyzeCoreDump(coreDump, executable, logger, infoKey)
	}
}

func analyzeCoreDump(coreDumpFile, executable string, logger *RedisLogger, infoKey string) {
	cmd := exec.Command("gdb", "-batch", "-ex", "bt full", executable, coreDumpFile)
	output, err := cmd.CombinedOutput()
	if err != nil {
		logger.logMessage(infoKey, fmt.Sprintf("Error analyzing core dump %s: %v", coreDumpFile, err), "crash")
		return
	}

	lines := strings.Split(string(output), "\n")
	var backtrace []string
	inBacktrace := false

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") {
			inBacktrace = true
			backtrace = append(backtrace, line)
		} else if inBacktrace && line == "" {
			break
		}
	}

	logger.logMessage(infoKey, fmt.Sprintf("Backtrace for %s:\n%s", coreDumpFile, strings.Join(backtrace, "\n")), "crash")

	newPath := fmt.Sprintf("%s.analyzed", coreDumpFile)
	if err := os.Rename(coreDumpFile, newPath); err != nil {
		logger.logMessage(infoKey, fmt.Sprintf("Error moving analyzed core dump %s: %v", coreDumpFile, err), "error")
	}
}

func (rl *RedisLogger) writeSeparator(message string) (string, string) {
    infoKey := fmt.Sprintf("logs:app:%s%s", rl.streamName, streamSuffixInfo)
    statusKey := fmt.Sprintf("logs:app:%s%s", rl.streamName, streamSuffixStatus)

    pipe := rl.logClient.Pipeline()

    // Write directly to both streams with MAXLEN
    for _, streamKey := range []string{infoKey, statusKey} {
        pipe.XAdd(ctx, &redis.XAddArgs{
            Stream:  streamKey,
            Values:  map[string]interface{}{"message": message},
            ID:      "*",
            MaxLen:  1000,        // Keep last 1000 entries
            Approx:  true,        // Use approximate trimming for better performance
        })
    }

    _, err := pipe.Exec(ctx)
    if err != nil {
        fmt.Printf("Error writing separator to Redis streams: %v\n", err)
    }

    return infoKey, statusKey
}

func (rl *RedisLogger) createRunKeys() (string, string) {
    // Just construct the keys and pass them to writeSeparator
    timestamp := time.Now().Format("2006-01-02_15-04-05")
    separator := fmt.Sprintf("{{__NEW_RUN_%s}}", timestamp)
    debugPrintf("Creating run keys with separator: %s", separator)
    return rl.writeSeparator(separator)
}

func runExecutableAndLog(targetUser, executable string, args []string, logger *RedisLogger) error {
    debugPrintf("Starting executable: %s with args: %v", executable, args)

    // Create stream keys and write start separator
    infoKey, _ := logger.createRunKeys()
    debugPrintf("Using Redis stream key: %s", infoKey)

    // Record process start time for core dump detection
    processStartTime := time.Now()

    // First clean up core dumps
    if err := cleanupPreviousCoreDumps(executable, logger, infoKey); err != nil {
        logger.logMessage(infoKey, fmt.Sprintf("Error cleaning up previous core dumps: %v", err), "error")
    }

    setupCoreDumpHandler(executable, logger, infoKey)

    cmd := createCommand(targetUser, executable, args)

    stdoutPipe, err := cmd.StdoutPipe()
    if err != nil {
        logger.logMessage(infoKey, fmt.Sprintf("Error setting up stdoutPipe: %v", err), "error")
        return err
    }
    stderrPipe, err := cmd.StderrPipe()
    if err != nil {
        logger.logMessage(infoKey, fmt.Sprintf("Error setting up stderrPipe: %v", err), "error")
        return err
    }

    if err := cmd.Start(); err != nil {
        logger.logMessage(infoKey, fmt.Sprintf("Error starting command: %v", err), "error")
        debugPrintf("Failed to start process: %v", err)
        return err
    }
    debugPrintf("Process started with PID: %d", cmd.Process.Pid)

    var wg sync.WaitGroup
    wg.Add(2)

    go readAndLog(stdoutPipe, infoKey, "stdout", logger, &wg)
    go readAndLog(stderrPipe, infoKey, "stderr", logger, &wg)

    wg.Wait()

    err = cmd.Wait()
    exitCode := getExitCode(err)
    if err != nil {
        logger.logMessage(infoKey, fmt.Sprintf("Error waiting for command to finish: %v", err), "error")
    }

    // If process crashed, wait a moment for core dump to be written
    if exitCode != 0 && exitCode != 1 {
        // Exit codes > 128 usually indicate death by signal (128 + signal number)
        // Common crash signals: SIGSEGV(11)=139, SIGABRT(6)=134, SIGBUS(7)=135
        if exitCode > 128 {
            logger.logMessage(infoKey, fmt.Sprintf("Process terminated by signal %d, waiting for core dump...", exitCode-128), "status")
            time.Sleep(2 * time.Second) // Give kernel time to write core dump
        }
    }

    // Check for core dumps after process has finished
    checkForCoreDumps(executable, logger, infoKey, processStartTime)

    // Log exit status message
    exitMessage := fmt.Sprintf("Executable exited with code %d.", exitCode)
    logger.logMessage(infoKey, exitMessage, "status")
    debugPrintf("Process finished - Exit code: %d", exitCode)
    fmt.Println(exitMessage)

    // Write end separator with exit code
    timestamp := time.Now().Format("2006-01-02_15-04-05")
    endSeparator := fmt.Sprintf("{{__END_RUN_%s_exit_%d}}", timestamp, exitCode)
    logger.writeSeparator(endSeparator)

    if exitCode != 0 {
        return fmt.Errorf("executable exited with non-zero code: %d", exitCode)
    }
    return nil
}

func createCommand(targetUser, executable string, args []string) *exec.Cmd {
	if os.Geteuid() == 0 && targetUser != "root" {
		suArgs := append([]string{"-l", targetUser, "-c", executable}, args...)
		debugPrintf("Creating command with su: su %v", suArgs)
		return exec.Command("su", suArgs...)
	}
	debugPrintf("Creating command: %s %v", executable, args)
	return exec.Command(executable, args...)
}

func readAndLog(pipe io.ReadCloser, infoKey, pipeName string, logger *RedisLogger, wg *sync.WaitGroup) {
	defer wg.Done()
	scanner := bufio.NewScanner(pipe)
	for scanner.Scan() {
		logger.parseAndLogOutput(scanner.Text(), infoKey)
	}
	if err := scanner.Err(); err != nil {
		logger.logMessage(infoKey, fmt.Sprintf("Error reading %s: %v", pipeName, err), "error")
	}
}

func getExitCode(err error) int {
	if err == nil {
		return 0
	}
	if exitError, ok := err.(*exec.ExitError); ok {
		return exitError.ExitCode()
	}
	return 1
}

func (rl *RedisLogger) logMessage(key, message, channel string) {
    if message = strings.TrimSpace(message); message == "" {
        fmt.Printf("Warning: Attempted to log empty message for key: %s, channel: %s\n", key, channel)
        return
    }

    var streamKey string
    switch channel {
    case "status":
        streamKey = strings.TrimSuffix(key, streamSuffixInfo) + streamSuffixStatus
    case "crash":
        streamKey = strings.TrimSuffix(key, streamSuffixInfo) + streamSuffixCrash
    case "error":
        streamKey = strings.TrimSuffix(key, streamSuffixInfo) + streamSuffixError
    default:
        streamKey = key
    }

    err := rl.logClient.XAdd(ctx, &redis.XAddArgs{
        Stream:  streamKey,
        Values:  map[string]interface{}{"message": message},
        MaxLen:  1000,        // Keep last 1000 entries
        Approx:  true,        // Use approximate trimming for better performance
    }).Err()

    if err != nil {
        fmt.Printf("Error logging message to Redis: %v\n", err)
    }
}

func (rl *RedisLogger) handleNormalLog(line, infoKey string) {
	if line = strings.TrimSpace(line); line != "" {
		rl.logMessage(infoKey, line, "")
	}
}

func (rl *RedisLogger) handleMultiLineLog(line, infoKey string) {
	const startToken, endToken = ">>|", "|<<"

	rl.bufferMutex.Lock()
	defer rl.bufferMutex.Unlock()

	if rl.multiLineBuffer == nil {
		rl.multiLineBuffer = &strings.Builder{}
	}

	startIndex := strings.Index(line, startToken)
	endIndex := strings.Index(line, endToken)

	if startIndex != -1 && endIndex != -1 && startIndex < endIndex {
		// Both tokens are present in the same line
		content := line[startIndex+len(startToken) : endIndex]
		if trimmedContent := strings.TrimSpace(content); trimmedContent != "" {
			rl.logMessage(infoKey, trimmedContent, "")
		}
		if endIndex+len(endToken) < len(line) {
			remainingContent := strings.TrimSpace(line[endIndex+len(endToken):])
			if remainingContent != "" {
				rl.handleNormalLog(remainingContent, infoKey)
			}
		}
	} else if startIndex != -1 {
		// Start of a new multiline message
		if rl.multiLineBuffer.Len() > 0 {
			bufferedContent := strings.TrimSpace(rl.multiLineBuffer.String())
			if bufferedContent != "" {
				rl.logMessage(infoKey, bufferedContent, "")
			}
			rl.multiLineBuffer.Reset()
		}
		rl.multiLineBuffer.WriteString(line[startIndex+len(startToken):])
		rl.multiLineBuffer.WriteString("\n")
	} else if endIndex != -1 {
		// End of the multiline message
		rl.multiLineBuffer.WriteString(line[:endIndex])
		bufferedContent := strings.TrimSpace(rl.multiLineBuffer.String())
		if bufferedContent != "" {
			rl.logMessage(infoKey, bufferedContent, "")
		}
		rl.multiLineBuffer.Reset()
		if endIndex+len(endToken) < len(line) {
			remainingContent := strings.TrimSpace(line[endIndex+len(endToken):])
			if remainingContent != "" {
				rl.handleNormalLog(remainingContent, infoKey)
			}
		}
	} else if rl.multiLineBuffer.Len() > 0 {
		// Middle of a multiline message
		rl.multiLineBuffer.WriteString(line)
		rl.multiLineBuffer.WriteString("\n")
	} else {
		// Not part of a multiline message, handle as normal log
		rl.handleNormalLog(line, infoKey)
	}

	if rl.multiLineBuffer.Len() > rl.maxBufferSize {
		rl.logMessage(infoKey, "Warning: Multi-line log exceeded maximum size", "warning")
		bufferedContent := strings.TrimSpace(rl.multiLineBuffer.String())
		if bufferedContent != "" {
			rl.logMessage(infoKey, bufferedContent, "")
		}
		rl.multiLineBuffer.Reset()
	}
}

func (rl *RedisLogger) parseAndLogOutput(line, infoKey string) {
	messagePattern := regexp.MustCompile(`\{\{(\w+):?(\d*)\}\}`)
	matches := messagePattern.FindAllStringSubmatchIndex(line, -1)

	if len(matches) > 0 {
		var newLine strings.Builder
		lastIndex := 0

		for _, match := range matches {
			newLine.WriteString(line[lastIndex:match[0]])

			key := line[match[2]:match[3]]
			value := strings.TrimSpace(line[match[4]:match[5]])
			appKey := fmt.Sprintf("wrapp:%s:%s", rl.streamName, key)

			if value == "" {
				if _, err := rl.valueClient.Incr(ctx, appKey).Result(); err != nil {
					rl.logMessage(infoKey, fmt.Sprintf("Error incrementing key: %s, error: %v", appKey, err), "error")
				}
			} else {
				if err := rl.valueClient.Set(ctx, appKey, value, 0).Err(); err != nil {
					rl.logMessage(infoKey, fmt.Sprintf("Error setting value for key: %s, value: %s, error: %v", appKey, value, err), "error")
				}
			}

			lastIndex = match[1]
		}

		newLine.WriteString(line[lastIndex:])
		rl.logLine(newLine.String(), infoKey)
	} else {
		rl.logLine(line, infoKey)
	}
}

func (rl *RedisLogger) logLine(line, infoKey string) {
	if strings.Contains(line, ">>|") || strings.Contains(line, "|<<") || (rl.multiLineBuffer != nil && rl.multiLineBuffer.Len() > 0) {
		rl.handleMultiLineLog(line, infoKey)
	} else {
		rl.handleNormalLog(line, infoKey)
	}
}

func continuouslyPingRedis(rdb *redis.Client, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for range ticker.C {
		if _, err := rdb.Ping(ctx).Result(); err != nil {
			fmt.Printf("Error pinging Redis: %v\n", err)
		}
	}
}
