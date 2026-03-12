package js

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"sync"

	_ "modernc.org/sqlite"
)

// ──────────────────────────────────────────────────────
// SQLite Module: Server + Client database for Goja JS
//
// JS API:
//   DB.Create(path)                  → open/create local SQLite DB
//   DB.Serve(port, opts)             → serve DB over TCP with auth
//   DB.Connect(host, opts)           → connect to remote DB server
//   db.Query(sql, ...params)         → SELECT → [{col: val}]
//   db.Exec(sql, ...params)          → INSERT/UPDATE/DELETE → {changes, lastID}
//   db.Tables()                      → list table names
//   db.Close()                       → close
// ──────────────────────────────────────────────────────

// sqliteDB wraps an open SQLite database
type sqliteDB struct {
	db   *sql.DB
	path string
	mu   sync.Mutex
}

// sqliteServer wraps a TCP listener serving a SQLite database
type sqliteServer struct {
	listener net.Listener
	sdb      *sqliteDB
	authKey  string
	ctx      context.Context
	cancel   context.CancelFunc
}

// RegisterSQLiteModule registers the DB module into jsCtx
func RegisterSQLiteModule(jsCtx map[string]interface{}) {
	jsCtx["DB"] = map[string]interface{}{

		// DB.Create(path) — Open/create a local SQLite database file
		"Create": func(dbPath string) map[string]interface{} {
			db, err := sql.Open("sqlite", dbPath)
			if err != nil {
				panic(fmt.Sprintf("DB.Create failed: %v", err))
			}
			// Performance pragmas
			db.Exec("PRAGMA journal_mode=WAL")
			db.Exec("PRAGMA busy_timeout=5000")
			db.Exec("PRAGMA foreign_keys=ON")

			if err := db.Ping(); err != nil {
				panic(fmt.Sprintf("DB.Create ping failed: %v", err))
			}

			sdb := &sqliteDB{db: db, path: dbPath}
			return wrapSQLiteDB(sdb)
		},

		// DB.Serve(port, opts) — Serve SQLite over TCP with auth
		// opts: { database: "path.db", auth: "key" }
		"Serve": func(port int, opts map[string]interface{}) map[string]interface{} {
			dbPath := "data.db"
			authKey := ""

			if opts != nil {
				if v, ok := opts["database"]; ok {
					dbPath = fmt.Sprintf("%v", v)
				}
				if v, ok := opts["auth"]; ok {
					authKey = fmt.Sprintf("%v", v)
				}
			}

			// Auto-generate auth key if not provided
			if authKey == "" {
				keyBytes := make([]byte, 16)
				rand.Read(keyBytes)
				authKey = hex.EncodeToString(keyBytes)
			}

			// Open database
			db, err := sql.Open("sqlite", dbPath)
			if err != nil {
				panic(fmt.Sprintf("DB.Serve open failed: %v", err))
			}
			db.Exec("PRAGMA journal_mode=WAL")
			db.Exec("PRAGMA busy_timeout=5000")
			db.Exec("PRAGMA foreign_keys=ON")

			sdb := &sqliteDB{db: db, path: dbPath}

			// Start TCP listener
			addr := fmt.Sprintf("0.0.0.0:%d", port)
			listener, err := net.Listen("tcp", addr)
			if err != nil {
				panic(fmt.Sprintf("DB.Serve listen failed: %v", err))
			}

			ctx, cancel := context.WithCancel(context.Background())
			srv := &sqliteServer{
				listener: listener,
				sdb:      sdb,
				authKey:  authKey,
				ctx:      ctx,
				cancel:   cancel,
			}
			go srv.acceptLoop()

			return map[string]interface{}{
				"db":   wrapSQLiteDB(sdb),
				"auth": authKey,
				"addr": listener.Addr().String(),
				"Close": func() {
					cancel()
					listener.Close()
					db.Close()
				},
			}
		},

		// DB.Connect(hostPort, opts) — Connect to remote DB server
		// opts: { auth: "key" }
		"Connect": func(hostPort string, opts map[string]interface{}) map[string]interface{} {
			authKey := ""
			if opts != nil {
				if v, ok := opts["auth"]; ok {
					authKey = fmt.Sprintf("%v", v)
				}
			}

			conn, err := net.Dial("tcp", hostPort)
			if err != nil {
				panic(fmt.Sprintf("DB.Connect failed: %v", err))
			}

			// Auth handshake
			if authKey != "" {
				conn.Write([]byte("AUTH:" + authKey + "\n"))
				buf := make([]byte, 256)
				n, err := conn.Read(buf)
				if err != nil {
					conn.Close()
					panic(fmt.Sprintf("DB.Connect auth read failed: %v", err))
				}
				resp := strings.TrimSpace(string(buf[:n]))
				if resp != "AUTH:OK" {
					conn.Close()
					panic(fmt.Sprintf("DB.Connect auth rejected: %s", resp))
				}
			}

			return map[string]interface{}{
				// Remote Query — sends SQL, returns JSON string
				"Query": func(query string) string {
					conn.Write([]byte(query + "\n"))
					buf := make([]byte, 1024*1024)
					n, err := conn.Read(buf)
					if err != nil {
						panic(fmt.Sprintf("Remote query read error: %v", err))
					}
					resp := strings.TrimSpace(string(buf[:n]))
					if strings.HasPrefix(resp, "ERROR:") {
						panic(fmt.Sprintf("DB error: %s", resp[6:]))
					}
					return resp
				},
				// Remote Exec
				"Exec": func(query string) string {
					conn.Write([]byte(query + "\n"))
					buf := make([]byte, 64*1024)
					n, err := conn.Read(buf)
					if err != nil {
						panic(fmt.Sprintf("Remote exec read error: %v", err))
					}
					resp := strings.TrimSpace(string(buf[:n]))
					if strings.HasPrefix(resp, "ERROR:") {
						panic(fmt.Sprintf("DB error: %s", resp[6:]))
					}
					return resp
				},
				"Close": func() {
					conn.Write([]byte("CLOSE\n"))
					conn.Close()
				},
			}
		},
	}
}

// ── Local DB wrapper ──

func wrapSQLiteDB(sdb *sqliteDB) map[string]interface{} {
	return map[string]interface{}{
		"Path": sdb.path,

		// db.Query(sql, params...) → []map[string]interface{}
		"Query": func(args ...interface{}) []map[string]interface{} {
			if len(args) < 1 {
				panic("Query requires SQL string")
			}
			sqlStr := fmt.Sprintf("%v", args[0])
			params := args[1:]

			sdb.mu.Lock()
			defer sdb.mu.Unlock()

			rows, err := sdb.db.Query(sqlStr, params...)
			if err != nil {
				panic(fmt.Sprintf("Query error: %v", err))
			}
			defer rows.Close()
			return sqliteRowsToSlice(rows)
		},

		// db.Exec(sql, params...) → { changes, lastID }
		"Exec": func(args ...interface{}) map[string]interface{} {
			if len(args) < 1 {
				panic("Exec requires SQL string")
			}
			sqlStr := fmt.Sprintf("%v", args[0])
			params := args[1:]

			sdb.mu.Lock()
			defer sdb.mu.Unlock()

			result, err := sdb.db.Exec(sqlStr, params...)
			if err != nil {
				panic(fmt.Sprintf("Exec error: %v", err))
			}

			changes, _ := result.RowsAffected()
			lastID, _ := result.LastInsertId()
			return map[string]interface{}{
				"changes": changes,
				"lastID":  lastID,
			}
		},

		// db.Tables() → []string
		"Tables": func() []string {
			sdb.mu.Lock()
			defer sdb.mu.Unlock()

			rows, err := sdb.db.Query("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
			if err != nil {
				panic(fmt.Sprintf("Tables error: %v", err))
			}
			defer rows.Close()

			var tables []string
			for rows.Next() {
				var name string
				rows.Scan(&name)
				tables = append(tables, name)
			}
			if tables == nil {
				tables = []string{}
			}
			return tables
		},

		// db.Close()
		"Close": func() {
			sdb.mu.Lock()
			defer sdb.mu.Unlock()
			sdb.db.Close()
		},
	}
}

// ── TCP Server ──

func (s *sqliteServer) acceptLoop() {
	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}
		conn, err := s.listener.Accept()
		if err != nil {
			continue
		}
		go s.handleConn(conn)
	}
}

func (s *sqliteServer) handleConn(conn net.Conn) {
	defer conn.Close()
	buf := make([]byte, 64*1024)

	// Auth handshake
	if s.authKey != "" {
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		msg := strings.TrimSpace(string(buf[:n]))
		if !strings.HasPrefix(msg, "AUTH:") || strings.TrimPrefix(msg, "AUTH:") != s.authKey {
			conn.Write([]byte("AUTH:DENIED\n"))
			return
		}
		conn.Write([]byte("AUTH:OK\n"))
	}

	// Command loop
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		query := strings.TrimSpace(string(buf[:n]))
		if query == "CLOSE" {
			return
		}

		result := s.execQuery(query)
		conn.Write([]byte(result + "\n"))
	}
}

func (s *sqliteServer) execQuery(query string) string {
	s.sdb.mu.Lock()
	defer s.sdb.mu.Unlock()

	upper := strings.ToUpper(strings.TrimSpace(query))
	isSelect := strings.HasPrefix(upper, "SELECT") || strings.HasPrefix(upper, "PRAGMA")

	if isSelect {
		rows, err := s.sdb.db.Query(query)
		if err != nil {
			return "ERROR:" + err.Error()
		}
		defer rows.Close()
		return sqliteRowsToJSON(rows)
	}

	result, err := s.sdb.db.Exec(query)
	if err != nil {
		return "ERROR:" + err.Error()
	}
	changes, _ := result.RowsAffected()
	lastID, _ := result.LastInsertId()
	return fmt.Sprintf(`{"changes":%d,"lastID":%d}`, changes, lastID)
}

// ── Helpers ──

func sqliteRowsToSlice(rows *sql.Rows) []map[string]interface{} {
	cols, _ := rows.Columns()
	var results []map[string]interface{}

	for rows.Next() {
		values := make([]interface{}, len(cols))
		ptrs := make([]interface{}, len(cols))
		for i := range values {
			ptrs[i] = &values[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			continue
		}
		row := make(map[string]interface{})
		for i, col := range cols {
			v := values[i]
			if b, ok := v.([]byte); ok {
				v = string(b)
			}
			row[col] = v
		}
		results = append(results, row)
	}
	if results == nil {
		results = []map[string]interface{}{}
	}
	return results
}

func sqliteRowsToJSON(rows *sql.Rows) string {
	results := sqliteRowsToSlice(rows)
	if len(results) == 0 {
		return "[]"
	}
	var sb strings.Builder
	sb.WriteString("[")
	for i, row := range results {
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString("{")
		j := 0
		for k, v := range row {
			if j > 0 {
				sb.WriteString(",")
			}
			sb.WriteString(`"`)
			sb.WriteString(k)
			sb.WriteString(`":`)
			switch val := v.(type) {
			case string:
				sb.WriteString(`"`)
				sb.WriteString(strings.ReplaceAll(strings.ReplaceAll(val, `\`, `\\`), `"`, `\"`))
				sb.WriteString(`"`)
			case int64:
				sb.WriteString(fmt.Sprintf("%d", val))
			case float64:
				sb.WriteString(fmt.Sprintf("%g", val))
			case nil:
				sb.WriteString("null")
			default:
				sb.WriteString(fmt.Sprintf(`"%v"`, val))
			}
			j++
		}
		sb.WriteString("}")
	}
	sb.WriteString("]")
	return sb.String()
}
