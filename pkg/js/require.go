package js

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/dop251/goja"
)

// Module represents a CommonJS module
type Module struct {
	Exports *goja.Object
	Loaded  bool
	ID      string
}

// RequireManager handles module loading and caching
type RequireManager struct {
	vm      *goja.Runtime
	cache   map[string]*Module
	mu      sync.Mutex
	baseDir string
}

func NewRequireManager(vm *goja.Runtime, baseDir string) *RequireManager {
	return &RequireManager{
		vm:      vm,
		cache:   make(map[string]*Module),
		baseDir: baseDir,
	}
}

// Require implements the CommonJS require() function
func (rm *RequireManager) Require(path string) (goja.Value, error) {
	absPath, err := rm.resolvePath(path)
	if err != nil {
		return nil, err
	}

	rm.mu.Lock()
	if mod, ok := rm.cache[absPath]; ok {
		rm.mu.Unlock()
		return mod.Exports, nil
	}

	// Create new module and cache it immediately to handle circular dependencies
	mod := &Module{
		Exports: rm.vm.NewObject(),
		ID:      absPath,
	}
	rm.cache[absPath] = mod
	rm.mu.Unlock()

	err = rm.loadModule(mod, absPath)
	if err != nil {
		// Remove from cache if load fails
		rm.mu.Lock()
		delete(rm.cache, absPath)
		rm.mu.Unlock()
		return nil, err
	}

	mod.Loaded = true
	return mod.Exports, nil
}

func (rm *RequireManager) resolvePath(path string) (string, error) {
	var targetPath string
	if filepath.IsAbs(path) {
		targetPath = path
	} else if strings.HasPrefix(path, "./") || strings.HasPrefix(path, "../") {
		// Relative to baseDir (main script location)
		targetPath = filepath.Join(rm.baseDir, path)
	} else {
		// For now, treat non-relative paths as relative to baseDir or look in a specific 'modules' folder
		targetPath = filepath.Join(rm.baseDir, path)
	}

	// Try with .js extension first
	if !strings.HasSuffix(targetPath, ".js") {
		if _, err := os.ReadFile(targetPath + ".js"); err == nil {
			targetPath += ".js"
		}
	}

	// Try index.js if it's a directory
	if info, err := os.ReadDir(targetPath); err == nil {
		_ = info
		targetPath = filepath.Join(targetPath, "index.js")
	}

	abs, err := filepath.Abs(targetPath)
	if err != nil {
		return "", err
	}

	return abs, nil
}

func (rm *RequireManager) loadModule(mod *Module, path string) error {
	content, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	// Wrap code in a function to provide module, exports, require, __filename, __dirname
	wrappedCode := fmt.Sprintf("(function(exports, require, module, __filename, __dirname) {\n%s\n})", string(content))

	prog, err := goja.Compile(path, wrappedCode, false)
	if err != nil {
		return err
	}

	val, err := rm.vm.RunProgram(prog)
	if err != nil {
		return err
	}

	fn, ok := goja.AssertFunction(val)
	if !ok {
		return fmt.Errorf("failed to wrap module code")
	}

	// Create module object for JS
	jsMod := rm.vm.NewObject()
	jsMod.Set("exports", mod.Exports)
	jsMod.Set("id", mod.ID)

	// require wrapper to maintain context
	jsRequire := func(call goja.FunctionCall) goja.Value {
		if len(call.Arguments) == 0 {
			panic(rm.vm.ToValue("require() requires 1 argument"))
		}
		p := call.Arguments[0].String()

		// Update baseDir for nested requires
		oldBase := rm.baseDir
		rm.baseDir = filepath.Dir(path)
		defer func() { rm.baseDir = oldBase }()

		res, err := rm.Require(p)
		if err != nil {
			panic(rm.vm.ToValue(fmt.Sprintf("failed to require %s: %v", p, err)))
		}
		return res
	}

	// Call the wrapper function
	_, err = fn(goja.Undefined(),
		mod.Exports,
		rm.vm.ToValue(jsRequire),
		jsMod,
		rm.vm.ToValue(path),
		rm.vm.ToValue(filepath.Dir(path)),
	)
	if err != nil {
		return err
	}

	// Update mod.Exports in case it was reassigned in JS (module.exports = ...)
	mod.Exports = jsMod.Get("exports").ToObject(rm.vm)

	return nil
}
