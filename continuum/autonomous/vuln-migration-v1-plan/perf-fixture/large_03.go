        package perf03

        import (
            "database/sql"
            "encoding/json"
            "net/http"
        )

        var db03 *sql.DB

        func Handler00(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodGet {
        http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
        return
    }
    user := r.URL.Query().Get("u")
    if user == "" {
        http.Error(w, "missing u", http.StatusBadRequest)
        return
    }
    rows, err := db03.Query("SELECT name FROM users WHERE id = $1", user)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    defer rows.Close()
    var out []map[string]string
    for rows.Next() {
        var name string
        if err := rows.Scan(&name); err != nil {
            continue
        }
        out = append(out, map[string]string{"name": name, "uid": user})
    }
    w.Header().Set("Content-Type", "application/json")
    _ = json.NewEncoder(w).Encode(out)
}

func Handler01(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodGet {
        http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
        return
    }
    user := r.URL.Query().Get("u")
    if user == "" {
        http.Error(w, "missing u", http.StatusBadRequest)
        return
    }
    rows, err := db03.Query("SELECT name FROM users WHERE id = $1", user)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    defer rows.Close()
    var out []map[string]string
    for rows.Next() {
        var name string
        if err := rows.Scan(&name); err != nil {
            continue
        }
        out = append(out, map[string]string{"name": name, "uid": user})
    }
    w.Header().Set("Content-Type", "application/json")
    _ = json.NewEncoder(w).Encode(out)
}

func Handler02(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodGet {
        http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
        return
    }
    user := r.URL.Query().Get("u")
    if user == "" {
        http.Error(w, "missing u", http.StatusBadRequest)
        return
    }
    rows, err := db03.Query("SELECT name FROM users WHERE id = $1", user)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    defer rows.Close()
    var out []map[string]string
    for rows.Next() {
        var name string
        if err := rows.Scan(&name); err != nil {
            continue
        }
        out = append(out, map[string]string{"name": name, "uid": user})
    }
    w.Header().Set("Content-Type", "application/json")
    _ = json.NewEncoder(w).Encode(out)
}

func Handler03(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodGet {
        http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
        return
    }
    user := r.URL.Query().Get("u")
    if user == "" {
        http.Error(w, "missing u", http.StatusBadRequest)
        return
    }
    rows, err := db03.Query("SELECT name FROM users WHERE id = $1", user)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    defer rows.Close()
    var out []map[string]string
    for rows.Next() {
        var name string
        if err := rows.Scan(&name); err != nil {
            continue
        }
        out = append(out, map[string]string{"name": name, "uid": user})
    }
    w.Header().Set("Content-Type", "application/json")
    _ = json.NewEncoder(w).Encode(out)
}

func Handler04(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodGet {
        http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
        return
    }
    user := r.URL.Query().Get("u")
    if user == "" {
        http.Error(w, "missing u", http.StatusBadRequest)
        return
    }
    rows, err := db03.Query("SELECT name FROM users WHERE id = $1", user)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    defer rows.Close()
    var out []map[string]string
    for rows.Next() {
        var name string
        if err := rows.Scan(&name); err != nil {
            continue
        }
        out = append(out, map[string]string{"name": name, "uid": user})
    }
    w.Header().Set("Content-Type", "application/json")
    _ = json.NewEncoder(w).Encode(out)
}

func Handler05(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodGet {
        http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
        return
    }
    user := r.URL.Query().Get("u")
    if user == "" {
        http.Error(w, "missing u", http.StatusBadRequest)
        return
    }
    rows, err := db03.Query("SELECT name FROM users WHERE id = $1", user)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    defer rows.Close()
    var out []map[string]string
    for rows.Next() {
        var name string
        if err := rows.Scan(&name); err != nil {
            continue
        }
        out = append(out, map[string]string{"name": name, "uid": user})
    }
    w.Header().Set("Content-Type", "application/json")
    _ = json.NewEncoder(w).Encode(out)
}

func Handler06(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodGet {
        http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
        return
    }
    user := r.URL.Query().Get("u")
    if user == "" {
        http.Error(w, "missing u", http.StatusBadRequest)
        return
    }
    rows, err := db03.Query("SELECT name FROM users WHERE id = $1", user)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    defer rows.Close()
    var out []map[string]string
    for rows.Next() {
        var name string
        if err := rows.Scan(&name); err != nil {
            continue
        }
        out = append(out, map[string]string{"name": name, "uid": user})
    }
    w.Header().Set("Content-Type", "application/json")
    _ = json.NewEncoder(w).Encode(out)
}

func Handler07(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodGet {
        http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
        return
    }
    user := r.URL.Query().Get("u")
    if user == "" {
        http.Error(w, "missing u", http.StatusBadRequest)
        return
    }
    rows, err := db03.Query("SELECT name FROM users WHERE id = $1", user)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    defer rows.Close()
    var out []map[string]string
    for rows.Next() {
        var name string
        if err := rows.Scan(&name); err != nil {
            continue
        }
        out = append(out, map[string]string{"name": name, "uid": user})
    }
    w.Header().Set("Content-Type", "application/json")
    _ = json.NewEncoder(w).Encode(out)
}

func Handler08(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodGet {
        http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
        return
    }
    user := r.URL.Query().Get("u")
    if user == "" {
        http.Error(w, "missing u", http.StatusBadRequest)
        return
    }
    rows, err := db03.Query("SELECT name FROM users WHERE id = $1", user)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    defer rows.Close()
    var out []map[string]string
    for rows.Next() {
        var name string
        if err := rows.Scan(&name); err != nil {
            continue
        }
        out = append(out, map[string]string{"name": name, "uid": user})
    }
    w.Header().Set("Content-Type", "application/json")
    _ = json.NewEncoder(w).Encode(out)
}

func Handler09(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodGet {
        http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
        return
    }
    user := r.URL.Query().Get("u")
    if user == "" {
        http.Error(w, "missing u", http.StatusBadRequest)
        return
    }
    rows, err := db03.Query("SELECT name FROM users WHERE id = $1", user)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    defer rows.Close()
    var out []map[string]string
    for rows.Next() {
        var name string
        if err := rows.Scan(&name); err != nil {
            continue
        }
        out = append(out, map[string]string{"name": name, "uid": user})
    }
    w.Header().Set("Content-Type", "application/json")
    _ = json.NewEncoder(w).Encode(out)
}

func Handler10(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodGet {
        http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
        return
    }
    user := r.URL.Query().Get("u")
    if user == "" {
        http.Error(w, "missing u", http.StatusBadRequest)
        return
    }
    rows, err := db03.Query("SELECT name FROM users WHERE id = $1", user)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    defer rows.Close()
    var out []map[string]string
    for rows.Next() {
        var name string
        if err := rows.Scan(&name); err != nil {
            continue
        }
        out = append(out, map[string]string{"name": name, "uid": user})
    }
    w.Header().Set("Content-Type", "application/json")
    _ = json.NewEncoder(w).Encode(out)
}

func Handler11(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodGet {
        http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
        return
    }
    user := r.URL.Query().Get("u")
    if user == "" {
        http.Error(w, "missing u", http.StatusBadRequest)
        return
    }
    rows, err := db03.Query("SELECT name FROM users WHERE id = $1", user)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    defer rows.Close()
    var out []map[string]string
    for rows.Next() {
        var name string
        if err := rows.Scan(&name); err != nil {
            continue
        }
        out = append(out, map[string]string{"name": name, "uid": user})
    }
    w.Header().Set("Content-Type", "application/json")
    _ = json.NewEncoder(w).Encode(out)
}

func Handler12(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodGet {
        http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
        return
    }
    user := r.URL.Query().Get("u")
    if user == "" {
        http.Error(w, "missing u", http.StatusBadRequest)
        return
    }
    rows, err := db03.Query("SELECT name FROM users WHERE id = $1", user)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    defer rows.Close()
    var out []map[string]string
    for rows.Next() {
        var name string
        if err := rows.Scan(&name); err != nil {
            continue
        }
        out = append(out, map[string]string{"name": name, "uid": user})
    }
    w.Header().Set("Content-Type", "application/json")
    _ = json.NewEncoder(w).Encode(out)
}

func Handler13(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodGet {
        http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
        return
    }
    user := r.URL.Query().Get("u")
    if user == "" {
        http.Error(w, "missing u", http.StatusBadRequest)
        return
    }
    rows, err := db03.Query("SELECT name FROM users WHERE id = $1", user)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    defer rows.Close()
    var out []map[string]string
    for rows.Next() {
        var name string
        if err := rows.Scan(&name); err != nil {
            continue
        }
        out = append(out, map[string]string{"name": name, "uid": user})
    }
    w.Header().Set("Content-Type", "application/json")
    _ = json.NewEncoder(w).Encode(out)
}

func Handler14(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodGet {
        http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
        return
    }
    user := r.URL.Query().Get("u")
    if user == "" {
        http.Error(w, "missing u", http.StatusBadRequest)
        return
    }
    rows, err := db03.Query("SELECT name FROM users WHERE id = $1", user)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    defer rows.Close()
    var out []map[string]string
    for rows.Next() {
        var name string
        if err := rows.Scan(&name); err != nil {
            continue
        }
        out = append(out, map[string]string{"name": name, "uid": user})
    }
    w.Header().Set("Content-Type", "application/json")
    _ = json.NewEncoder(w).Encode(out)
}

