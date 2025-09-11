package ext

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

//go:embed templates
var tmpls embed.FS

type Option func(*option)

func WithGoCommandPath(path string) Option {
	return func(opt *option) {
		opt.goPath = path
	}
}

type File struct {
	path         string
	tmpFilePaths []string
}

func (f *File) Path() string {
	return f.path
}

func (f *File) Close() {
	_ = os.Remove(f.path)
	for _, path := range f.tmpFilePaths {
		_ = os.Remove(path)
	}
}

func CreateOverlay(ctx context.Context, opts ...Option) (*File, error) {
	netTmpl, err := tmpls.ReadFile("templates/net.go.tmpl")
	if err != nil {
		return nil, err
	}
	cryptoX509Tmpl, err := tmpls.ReadFile("templates/crypto_x509.go.tmpl")
	if err != nil {
		return nil, err
	}
	osExecTmpl, err := tmpls.ReadFile("templates/os_exec.go.tmpl")
	if err != nil {
		return nil, err
	}
	return createOverlay(ctx, []*provider{
		{
			PkgPath: "net",
			Functions: []*Function{
				{
					Name: "DialContext",
					Method: &Method{
						Type:    "Dialer",
						Name:    "d",
						Pointer: true,
					},
					Bypass: "dialContextWasip1",
					Args: []ast.Expr{
						&ast.Ident{Name: "ctx"},
						&ast.Ident{Name: "network"},
						&ast.Ident{Name: "address"},
					},
				},
				{
					Name:   "Listen",
					Bypass: "listenWasip1",
					Args: []ast.Expr{
						&ast.Ident{Name: "network"},
						&ast.Ident{Name: "address"},
					},
				},
			},
			Entry: netTmpl,
		},
		{
			PkgPath: filepath.Join("crypto", "x509"),
			Functions: []*Function{
				{
					Name: "Verify",
					Method: &Method{
						Type:    "Certificate",
						Name:    "c",
						Pointer: true,
					},
					Bypass: "verifyWasip1",
					Args: []ast.Expr{
						&ast.UnaryExpr{
							Op: token.AND,
							X:  &ast.Ident{Name: "opts"},
						},
					},
				},
			},
			Entry: cryptoX509Tmpl,
		},
		{
			PkgPath: filepath.Join("os", "exec"),
			Functions: []*Function{
				{
					Name: "Start",
					Method: &Method{
						Type:    "Cmd",
						Name:    "c",
						Pointer: true,
					},
					Bypass: "startWasip1",
				},
				{
					Name: "Wait",
					Method: &Method{
						Type:    "Cmd",
						Name:    "c",
						Pointer: true,
					},
					Bypass: "waitWasip1",
				},
			},
			Entry: osExecTmpl,
		},
	}, opts...)
}

type provider struct {
	PkgPath   string
	Functions []*Function
	Entry     []byte
}

type Function struct {
	Name   string
	Method *Method
	Bypass string
	Args   []ast.Expr
}

type Method struct {
	Type    string
	Name    string
	Pointer bool
}

type option struct {
	goPath string
}

type Content struct {
	Path    string
	Content []byte
}

func createOverlay(ctx context.Context, p []*provider, opts ...Option) (*File, error) {
	o := &option{}
	for _, opt := range opts {
		opt(o)
	}
	var contents []*Content
	for _, pp := range p {
		c, err := createOverlayContents(ctx, pp, o)
		if err != nil {
			return nil, err
		}
		contents = append(contents, c...)
	}

	tmpFilePaths := make([]string, 0, len(contents))
	overlayMap := make(map[string]string)
	for _, c := range contents {
		tmpFile, err := os.CreateTemp("", filepath.Base(c.Path)+"_")
		if err != nil {
			return nil, fmt.Errorf("failed to create temp file: %w", err)
		}
		defer tmpFile.Close()

		if _, err := tmpFile.Write(c.Content); err != nil {
			return nil, fmt.Errorf("failed to write file content: %w", err)
		}
		tmpFilePaths = append(tmpFilePaths, tmpFile.Name())
		overlayMap[c.Path] = tmpFile.Name()
	}

	tmpFile, err := os.CreateTemp("", "wasi_go_overlay")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp file: %w", err)
	}
	defer tmpFile.Close()

	b, err := json.Marshal(map[string]interface{}{
		"Replace": overlayMap,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create overlay file content: %w", err)
	}
	if _, err := tmpFile.Write(b); err != nil {
		return nil, fmt.Errorf("failed to write file content: %w", err)
	}
	return &File{
		path:         tmpFile.Name(),
		tmpFilePaths: tmpFilePaths,
	}, nil

}

func createOverlayContents(ctx context.Context, p *provider, opt *option) ([]*Content, error) {
	srcPath, err := pkgSrcPath(ctx, p, opt)
	if err != nil {
		return nil, err
	}
	pkgFiles, err := pkgGoFiles(ctx, srcPath)
	if err != nil {
		return nil, err
	}
	var contents []*Content
	for _, pkgFile := range pkgFiles {
		src, err := os.ReadFile(pkgFile)
		if err != nil {
			continue
		}

		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, pkgFile, src, 0)
		if err != nil {
			continue
		}

		orgDeclsNum := len(file.Decls)
		for _, decl := range file.Decls {
			funcDecl, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			fn := matchedFunc(p, funcDecl)
			if fn == nil {
				continue
			}
			funcDecl.Name = &ast.Ident{Name: "__original" + fn.Name + "__"}

			var newDecl *ast.FuncDecl
			if fn.Method != nil {
				receiverName := fn.Method.Name
				newDecl = &ast.FuncDecl{
					Recv: funcDecl.Recv,
					Name: &ast.Ident{Name: fn.Name},
					Type: funcDecl.Type,
					Body: &ast.BlockStmt{
						List: []ast.Stmt{
							&ast.ReturnStmt{
								Results: []ast.Expr{
									&ast.CallExpr{
										Fun: &ast.SelectorExpr{
											X:   &ast.Ident{Name: receiverName},
											Sel: &ast.Ident{Name: fn.Bypass},
										},
										Args: fn.Args,
									},
								},
							},
						},
					},
				}
			} else {
				newDecl = &ast.FuncDecl{
					Name: &ast.Ident{Name: fn.Name},
					Type: funcDecl.Type,
					Body: &ast.BlockStmt{
						List: []ast.Stmt{
							&ast.ReturnStmt{
								Results: []ast.Expr{
									&ast.CallExpr{
										Fun:  &ast.Ident{Name: fn.Bypass},
										Args: fn.Args,
									},
								},
							},
						},
					},
				}
			}
			file.Decls = append(file.Decls, newDecl)
		}
		if orgDeclsNum != len(file.Decls) {
			var buf bytes.Buffer
			if err := format.Node(&buf, fset, file); err != nil {
				return nil, fmt.Errorf("failed to format AST: %w", err)
			}
			contents = append(contents, &Content{
				Path:    pkgFile,
				Content: buf.Bytes(),
			})
		}
	}
	if len(contents) != 0 {
		contents = append(contents, &Content{
			Path:    filepath.Join(srcPath, "wasi_go_overlay_entry_wasip1.go"),
			Content: p.Entry,
		})
	}
	return contents, nil
}

func pkgSrcPath(ctx context.Context, p *provider, opt *option) (string, error) {
	goroot, err := getGoroot(ctx, opt)
	if err != nil {
		return "", err
	}
	return filepath.Join(goroot, "src", p.PkgPath), nil
}

func pkgGoFiles(ctx context.Context, srcPath string) ([]string, error) {
	var ret []string
	_ = filepath.Walk(srcPath, func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || filepath.Ext(info.Name()) != ".go" {
			return nil
		}

		if strings.HasSuffix(info.Name(), "_test.go") {
			return nil
		}

		ret = append(ret, path)
		return nil
	})
	return ret, nil
}

func getGoroot(ctx context.Context, opt *option) (string, error) {
	var goPath string
	if opt.goPath != "" {
		goPath = opt.goPath
	} else {
		goCmd, err := exec.LookPath("go")
		if err != nil {
			return "", fmt.Errorf("failed to find go binary path: %w", err)
		}
		goPath = goCmd
	}
	out, err := exec.CommandContext(ctx, goPath, "env", "GOROOT").CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("failed to get GOROOT: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

func matchedFunc(p *provider, decl *ast.FuncDecl) *Function {
	for _, fn := range p.Functions {
		if decl.Name.Name != fn.Name {
			continue
		}
		if fn.Method != nil {
			if decl.Recv == nil {
				continue
			}
			if len(decl.Recv.List) == 0 {
				continue
			}
			if fn.Method.Pointer {
				star, ok := decl.Recv.List[0].Type.(*ast.StarExpr)
				if !ok {
					continue
				}
				ident, ok := star.X.(*ast.Ident)
				if !ok {
					continue
				}
				if ident.Name == fn.Method.Type {
					return fn
				}
			}
		} else {
			if decl.Recv != nil {
				continue
			}
			return fn
		}
	}
	return nil
}
