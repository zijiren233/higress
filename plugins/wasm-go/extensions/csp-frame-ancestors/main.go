// Copyright (c) 2025 Alibaba Group Holding Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"errors"
	"regexp"
	"strings"

	"github.com/higress-group/proxy-wasm-go-sdk/proxywasm"
	"github.com/higress-group/proxy-wasm-go-sdk/proxywasm/types"
	"github.com/higress-group/wasm-go/pkg/log"
	"github.com/higress-group/wasm-go/pkg/wrapper"
	"github.com/tidwall/gjson"
)

func main() {}

func init() {
	wrapper.SetCtx(
		"csp-frame-ancestors",
		wrapper.ParseConfig(parseConfig),
		wrapper.ProcessRequestHeaders(onHttpRequestHeaders),
		wrapper.ProcessResponseHeaders(onHttpResponseHeaders),
	)
}

// CSPFrameAncestorsConfig defines the plugin configuration
type CSPFrameAncestorsConfig struct {
	// Compiled regular expressions for matching referer
	refererPatterns []*regexp.Regexp
	// Frame ancestors values to add
	frameAncestors            []string
	spaceJoinedFrameAncestors string
	frameAncestorsDirective   string
}

// parseConfig parses the plugin configuration
func parseConfig(json gjson.Result, config *CSPFrameAncestorsConfig) error {
	// Parse referer_patterns
	refererPatternsArray := json.Get("referer_patterns").Array()
	if len(refererPatternsArray) == 0 {
		return errors.New("referer_patterns is required and cannot be empty")
	}

	config.refererPatterns = make([]*regexp.Regexp, 0, len(refererPatternsArray))
	for _, pattern := range refererPatternsArray {
		patternStr := pattern.String()
		if patternStr == "" {
			continue
		}
		re, err := regexp.Compile(patternStr)
		if err != nil {
			return err
		}
		config.refererPatterns = append(config.refererPatterns, re)
	}

	if len(config.refererPatterns) == 0 {
		return errors.New("no valid referer patterns found")
	}

	// Parse frame_ancestors
	frameAncestorsArray := json.Get("frame_ancestors").Array()
	if len(frameAncestorsArray) == 0 {
		return errors.New("frame_ancestors is required and cannot be empty")
	}

	config.frameAncestors = make([]string, 0, len(frameAncestorsArray))
	for _, ancestor := range frameAncestorsArray {
		ancestorStr := ancestor.String()
		if ancestorStr != "" {
			config.frameAncestors = append(config.frameAncestors, ancestorStr)
		}
	}

	if len(config.frameAncestors) == 0 {
		return errors.New("no valid frame_ancestors found")
	}

	config.spaceJoinedFrameAncestors = strings.Join(config.frameAncestors, " ")
	config.frameAncestorsDirective = "frame-ancestors " + config.spaceJoinedFrameAncestors

	return nil
}

// onHttpRequestHeaders processes request headers to check referer
func onHttpRequestHeaders(ctx wrapper.HttpContext, config CSPFrameAncestorsConfig) types.Action {
	// Get the Referer header
	referer, err := proxywasm.GetHttpRequestHeader("referer")
	if err != nil || referer == "" {
		log.Debug("no referer header found, skipping CSP processing")
		ctx.SetContext("csp_matched", false)
		ctx.DontReadRequestBody()
		return types.ActionContinue
	}

	log.Debugf("checking referer: %s", referer)

	// Check if referer matches any pattern
	matched := false
	for _, pattern := range config.refererPatterns {
		if pattern.MatchString(referer) {
			matched = true
			log.Debugf("referer matched pattern: %s", pattern.String())
			break
		}
	}

	// Store match result in context for use in response phase
	ctx.SetContext("csp_matched", matched)
	ctx.DontReadRequestBody()

	return types.ActionContinue
}

// onHttpResponseHeaders processes response headers to modify CSP
func onHttpResponseHeaders(ctx wrapper.HttpContext, config CSPFrameAncestorsConfig) types.Action {
	// Check if referer was matched in request phase
	matched, ok := ctx.GetContext("csp_matched").(bool)
	if !ok || !matched {
		log.Debug("referer not matched, skipping CSP modification")
		ctx.DontReadResponseBody()
		return types.ActionContinue
	}

	log.Debug("referer matched, processing CSP header")

	// Get existing CSP header
	existingCSP, err := proxywasm.GetHttpResponseHeader("content-security-policy")

	log.Debugf("frame-ancestors directive: %s", config.frameAncestorsDirective)

	var newCSP string

	if err != nil || existingCSP == "" {
		// Case 1: No CSP header exists, add new one
		newCSP = config.frameAncestorsDirective
		log.Debug("no existing CSP, adding new header")
	} else {
		// Case 2: CSP header exists, need to process it
		log.Debugf("existing CSP: %s", existingCSP)
		newCSP = processExistingCSP(existingCSP, config)
	}

	// Set or replace the CSP header
	if err := proxywasm.ReplaceHttpResponseHeader("content-security-policy", newCSP); err != nil {
		log.Warnf("failed to replace CSP header: %v", err)
		if addErr := proxywasm.AddHttpResponseHeader("content-security-policy", newCSP); addErr != nil {
			log.Errorf("failed to add CSP header: %v", addErr)
		}
	}

	log.Debugf("final CSP: %s", newCSP)
	ctx.DontReadResponseBody()

	return types.ActionContinue
}

// processExistingCSP handles the logic of modifying existing CSP header
func processExistingCSP(existingCSP string, config CSPFrameAncestorsConfig) string {
	// Parse existing CSP into directives
	directives := parseCSPDirectives(existingCSP)

	// Check if frame-ancestors directive exists
	frameAncestorsKey := "frame-ancestors"
	existingFrameAncestors, exists := directives[frameAncestorsKey]

	if !exists {
		// Case 2a: frame-ancestors doesn't exist, append it
		log.Debug("frame-ancestors not found, appending")
		if strings.HasSuffix(strings.TrimSpace(existingCSP), ";") {
			return existingCSP + " " + config.frameAncestorsDirective
		}
		return existingCSP + "; " + config.frameAncestorsDirective
	}

	// Case 2b: frame-ancestors exists
	log.Debugf("existing frame-ancestors: %s", existingFrameAncestors)

	// Check if it's 'none'
	trimmedValue := strings.TrimSpace(existingFrameAncestors)
	if trimmedValue == "'none'" || trimmedValue == "none" {
		// Replace 'none' with configured values
		log.Debug("frame-ancestors is 'none', replacing")
		directives[frameAncestorsKey] = config.spaceJoinedFrameAncestors
	} else {
		// Append to existing frame-ancestors
		log.Debug("appending to existing frame-ancestors")
		directives[frameAncestorsKey] = existingFrameAncestors + " " + config.spaceJoinedFrameAncestors
	}

	// Rebuild CSP string
	return rebuildCSP(directives)
}

// parseCSPDirectives parses a CSP string into a map of directives
func parseCSPDirectives(csp string) map[string]string {
	directives := make(map[string]string)

	// Split by semicolon
	parts := strings.Split(csp, ";")

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		// Split directive name and values
		spaceIdx := strings.Index(part, " ")
		if spaceIdx == -1 {
			// Directive without value
			directives[strings.ToLower(part)] = ""
		} else {
			directiveName := strings.ToLower(strings.TrimSpace(part[:spaceIdx]))
			directiveValue := strings.TrimSpace(part[spaceIdx+1:])
			directives[directiveName] = directiveValue
		}
	}

	return directives
}

// rebuildCSP rebuilds a CSP string from a map of directives
func rebuildCSP(directives map[string]string) string {
	var parts []string

	// Maintain order: frame-ancestors first, then others
	if frameAncestors, ok := directives["frame-ancestors"]; ok && frameAncestors != "" {
		parts = append(parts, "frame-ancestors "+frameAncestors)
		delete(directives, "frame-ancestors")
	}

	// Add remaining directives
	for name, value := range directives {
		if value != "" {
			parts = append(parts, name+" "+value)
		} else {
			parts = append(parts, name)
		}
	}

	return strings.Join(parts, "; ")
}
