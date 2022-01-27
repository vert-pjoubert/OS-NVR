// Copyright 2020-2022 The OS-NVR Authors.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package ffmpeg

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"
)

// LogFunc used to log stdout and stderr.
type LogFunc func(string)

// Process interface only used for testing.
type Process interface {

	// Set timeout for process to exit after being stopped.
	Timeout(time.Duration) Process

	// Set function called on stdout line.
	StdoutLogger(LogFunc) Process

	// Set function called on stderr line.
	StderrLogger(LogFunc) Process

	// Start process with context.
	Start(ctx context.Context) error

	// Stop process.
	Stop()
}

// process manages subprocesses.
type process struct {
	timeout time.Duration
	cmd     *exec.Cmd

	stdoutLogger LogFunc
	stderrLogger LogFunc

	done chan struct{}
}

// NewProcessFunc is used for mocking.
type NewProcessFunc func(*exec.Cmd) Process

// NewProcess return process.
func NewProcess(cmd *exec.Cmd) Process {
	return process{
		timeout: 1000 * time.Millisecond,
		cmd:     cmd,
	}
}

func (p process) Timeout(timeout time.Duration) Process {
	p.timeout = timeout
	return p
}

func (p process) StdoutLogger(l LogFunc) Process {
	p.stdoutLogger = l
	return p
}

func (p process) StderrLogger(l LogFunc) Process {
	p.stderrLogger = l
	return p
}

func (p process) Start(ctx context.Context) error {
	if p.stdoutLogger != nil {
		pipe, err := p.cmd.StdoutPipe()
		if err != nil {
			return err
		}
		p.attachLogger(p.stdoutLogger, "stdout", pipe)
	}
	if p.stderrLogger != nil {
		pipe, err := p.cmd.StderrPipe()
		if err != nil {
			return err
		}
		p.attachLogger(p.stderrLogger, "stderr", pipe)
	}

	if err := p.cmd.Start(); err != nil {
		return err
	}

	p.done = make(chan struct{})

	go func() {
		select {
		case <-p.done:
		case <-ctx.Done():
			p.Stop()
		}
	}()

	err := p.cmd.Wait()
	close(p.done)

	// FFmpeg seems to return 255 on normal exit.
	if err != nil && err.Error() == "exit status 255" {
		return nil
	}

	return err
}

func (p process) attachLogger(logFunc LogFunc, label string, pipe io.ReadCloser) {
	scanner := bufio.NewScanner(pipe)
	go func() {
		for scanner.Scan() {
			msg := fmt.Sprintf("%v: %v", label, scanner.Text())
			logFunc(msg)
		}
	}()
}

// Note, can't use CommandContext to Stop process as it would
// kill the process before it has a chance to exit on its own.
func (p process) Stop() {
	p.cmd.Process.Signal(os.Interrupt) //nolint:errcheck

	select {
	case <-p.done:
	case <-time.After(p.timeout):
		p.cmd.Process.Signal(os.Kill) //nolint:errcheck
		<-p.done
	}
}

// MakePipe creates fifo pipe at specified location.
func MakePipe(path string) error {
	os.Remove(path)
	err := syscall.Mkfifo(path, 0o600)
	if err != nil {
		return err
	}
	return nil
}

// FFMPEG stores ffmpeg binary location.
type FFMPEG struct {
	command func(...string) *exec.Cmd
}

// New returns FFMPEG.
func New(bin string) *FFMPEG {
	command := func(args ...string) *exec.Cmd {
		return exec.Command(bin, args...)
	}
	return &FFMPEG{command: command}
}

// SizeFromStreamFunc is used for mocking.
type SizeFromStreamFunc func(string) (string, error)

// SizeFromStream uses ffmpeg to grab stream size.
func (f *FFMPEG) SizeFromStream(url string) (string, error) {
	cmd := f.command("-i", url, "-f", "ffmetadata", "-")

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%s %w", stderr.String(), err)
	}

	re := regexp.MustCompile(`\b\d+x\d+\b`)
	// Input "Stream #0:0: Video: h264 (Main), yuv420p(progressive), 720x1280 fps, 30.00"
	// Output "720x1280"

	output := re.FindString(stderr.String())
	if output != "" {
		return output, nil
	}

	return "", fmt.Errorf("no regex match %s: %w",
		stderr.String(), strconv.ErrSyntax)
}

// VideoDurationFunc is used for mocking.
type VideoDurationFunc func(string) (time.Duration, error)

// VideoDuration uses ffmpeg to get video duration.
func (f *FFMPEG) VideoDuration(path string) (time.Duration, error) {
	cmd := f.command("-i", path, "-f", "ffmetadata", "-")

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return 0, fmt.Errorf("%s %w", stderr.String(), err)
	}

	// Input "Duration: 01:02:59.99, start: 0.000000, bitrate: 614 kb/s"
	// Output "1h2m59s99ms"
	re := regexp.MustCompile(`\bDuration: (\d\d):(\d\d):(\d\d).(\d\d)`)
	m := re.FindStringSubmatch(stderr.String())
	if len(m) != 5 {
		return 0, fmt.Errorf("could not find duration: %v, %v: %w",
			m, stderr.String(), strconv.ErrSyntax)
	}
	output := m[1] + "h" + m[2] + "m" + m[3] + "s" + m[4] + "0ms"

	return time.ParseDuration(output)
}

/*
func HWaccels(bin string) ([]string, error) {
	cmd := exec.Command(bin, "-hwaccels")

	var stdout bytes.Buffer
	cmd.Stdout = &stdout

	if err := cmd.Run(); err != nil {
		return []string{}, fmt.Errorf("%v", err)
	}

	// Input
	//   accels Hardware acceleration methods:
	//   vdpau
	//   vaapi

	// Output ["vdpau", "vaapi"]
	input := strings.TrimSpace(stdout.String())
	lines := strings.Split(input, "\n")

	return lines[1:], nil
}
*/

// Rect top, left, bottom, right.
type Rect [4]int

// Point on image.
type Point [2]int

// Polygon slice of Points.
type Polygon []Point

// ToAbs returns polygon converted from percentage values to absolute values.
func (p Polygon) ToAbs(w, h int) Polygon {
	polygon := make(Polygon, len(p))
	for i, point := range p {
		px := point[0]
		py := point[1]
		polygon[i] = [2]int{
			int(float64(w) * (float64(px) / 100)),
			int(float64(h) * (float64(py) / 100)),
		}
	}
	return polygon
}

// CreateMask creates an image mask from a polygon.
// Pixels inside the polygon are masked.
func CreateMask(w int, h int, poly Polygon) image.Image {
	img := image.NewAlpha(image.Rect(0, 0, w, h))

	for y := 0; y < w; y++ {
		for x := 0; x < h; x++ {
			if vertexInsidePoly(y, x, poly) {
				img.Set(y, x, color.Alpha{255})
			} else {
				img.Set(y, x, color.Alpha{0})
			}
		}
	}
	return img
}

// CreateInvertedMask creates an image mask from a polygon.
// Pixels outside the polygon are masked.
func CreateInvertedMask(w int, h int, poly Polygon) image.Image {
	img := image.NewAlpha(image.Rect(0, 0, w, h))

	for y := 0; y < w; y++ {
		for x := 0; x < h; x++ {
			if vertexInsidePoly(y, x, poly) {
				img.Set(y, x, color.Alpha{0})
			} else {
				img.Set(y, x, color.Alpha{255})
			}
		}
	}
	return img
}

func vertexInsidePoly(x int, y int, poly Polygon) bool {
	inside := false
	j := len(poly) - 1
	for i := 0; i < len(poly); i++ {
		xi := poly[i][0]
		yi := poly[i][1]
		xj := poly[j][0]
		yj := poly[j][1]

		if ((yi > y) != (yj > y)) && (x < (xj-xi)*(y-yi)/(yj-yi)+xi) {
			inside = !inside
		}
		j = i
	}
	return inside
}

// SaveImage saves image to specified location.
func SaveImage(path string, img image.Image) error {
	os.Remove(path)

	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	err = png.Encode(file, img)
	if err != nil {
		return err
	}

	err = file.Close()
	if err != nil {
		return err
	}
	return nil
}

// ParseArgs slices arguments.
func ParseArgs(args string) []string {
	return strings.Split(strings.TrimSpace(args), " ")
}

// ParseScaleString converts string to number that's used in the FFmpeg scale filter.
func ParseScaleString(scale string) string {
	switch strings.ToLower(scale) {
	case "full":
		return "1"
	case "half":
		return "2"
	case "third":
		return "3"
	case "quarter":
		return "4"
	case "sixth":
		return "6"
	case "eighth":
		return "8"
	default:
		return "1"
	}
}

// WaitForKeyframeFunc is used for mocking.
type WaitForKeyframeFunc func(context.Context, string, int) (time.Duration, error)

// ErrKeyFrameTimeout .
var ErrKeyFrameTimeout = errors.New("timeout")

// WaitForKeyframe waits for ffmpeg to update the ".m3u8" manifest file with
// a new segment, and returns the combined duration of the last nSegments.
// Used to calculate start time of the recording.
func WaitForKeyframe(ctx context.Context, hlsPath string, nSegments int) (time.Duration, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return 0, err
	}
	defer watcher.Close()

	err = watcher.Add(hlsPath)
	if err != nil {
		return 0, err
	}
	for {
		select {
		case <-watcher.Events:
			return getSegmentDuration(hlsPath, nSegments)
		case err := <-watcher.Errors:
			return 0, err
		case <-time.After(30 * time.Second):
			return 0, ErrKeyFrameTimeout
		case <-ctx.Done():
			return 0, nil
		}
	}
}

// ErrInvalidFile invalid m3u8 file.
var ErrInvalidFile = errors.New("")

func getSegmentDuration(hlsPath string, nSegments int) (time.Duration, error) {
	/* INPUT
	   #EXTM3U
	   #EXT-X-VERSION:3
	   #EXT-X-ALLOW-CACHE:NO
	   #EXT-X-TARGETDURATION:2
	   #EXT-X-MEDIA-SEQUENCE:251
	   #EXTINF:4.250000,
	   10.ts
	   #EXTINF:3.500000,
	   11.ts
	*/
	// OUTPUT 3500

	m3u8, err := os.ReadFile(hlsPath)
	if err != nil {
		return 0, err
	}
	durations := parseDurations(string(m3u8))
	if len(durations) < nSegments {
		return 0, fmt.Errorf("not enough detections: %v %w", string(m3u8), ErrInvalidFile)
	}

	var totalDuration int
	for i := nSegments; i != 0; i-- {
		dIndex := len(durations) - i
		durationStr := strings.ReplaceAll(durations[dIndex], ".", "")
		durationInt, err := strconv.Atoi(durationStr)
		if err != nil {
			return 0, fmt.Errorf("could not parse duration: %w", err)
		}
		totalDuration += durationInt
	}

	return time.Duration(totalDuration) * time.Millisecond, nil
}

func parseDurations(m3u8 string) []string {
	lines := strings.Split(strings.TrimSpace(m3u8), "\n")
	var durations []string
	for _, line := range lines {
		if len(line) == 17 && line[:8] == "#EXTINF:" {
			durations = append(durations, line[8:13])
		}
	}
	// OUTPUT [4.250 3.500]
	return durations
}

// FeedRateToDuration calculates frame duration from feedrate (fps).
func FeedRateToDuration(feedrate string) (time.Duration, error) {
	feedRateFloat, err := strconv.ParseFloat(feedrate, 64)
	if err != nil {
		return 0, fmt.Errorf("could not parse feedrate: %w", err)
	}

	frameDurationFloat := 1 / feedRateFloat
	frameDuration := strconv.FormatFloat(frameDurationFloat, 'f', -1, 64)

	return time.ParseDuration(frameDuration + "s")
}
