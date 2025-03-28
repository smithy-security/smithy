
˜
Ñ˜Í∑û–Ø–gosec€
0file:///tmp/wspc/go-dvwa/vulnerable/sql.go:52-52G404VUse of weak random number generator (math/rand or math/rand/v2 instead of crypto/rand) 0:?51: 			"sneaker",
52: 			rand.Intn(500))
53: 		if err != nil {
BunknownR%:d01e22b2-88b0-4873-a13b-9e3d1279af09bœ			fmt.Sprintf("secret password %d", i))
		if err != nil {
			return nil, err
		}

		_, err = db.Exec(
			"INSERT INTO product (name, category, price) VALUES (?, ?, ?)",
			fmt.Sprintf("Product %d", i),
			"sneaker",
			rand.Intn(500))
		if err != nil {
			return nil, err
		}
	}

	return db, nil
}

type Product struct {
	Id       intj“î
-file:///tmp/wspc/go-dvwa/server/main.go:27-27G114GUse of net/http serve function that has no support for setting timeouts 0:Ü26: 	log.Println("Serving application on", addr)
27: 	err = http.ListenAndServe(addr, sqhttp.Middleware(router))
28: 	if err != nil {
BunknownR%:34ca912e-8df6-47f2-9bd9-7a1bd3771e81b“	if err != nil {
		log.Panic("could not get the executable filename:", err)
	}
	templateDir := filepath.Join(filepath.Dir(bin), "template")

	router := NewRouter(templateDir)

	addr := ":8080"
	log.Println("Serving application on", addr)
	err = http.ListenAndServe(addr, sqhttp.Middleware(router))
	if err != nil {
		log.Fatalln(err)
	}
}j§ﬂ
0file:///tmp/wspc/go-dvwa/vulnerable/sql.go:69-69G202SQL string concatenation 0:œ68: func GetProducts(ctx context.Context, db *sql.DB, category string) ([]Product, error) {
69: 	rows, err := db.QueryContext(ctx, "SELECT * FROM product WHERE category='"+category+"'")
70: 	if err != nil {
BunknownR%:ff3580cd-5ce4-4f88-b125-e66a23dbc41abÅ
type Product struct {
	Id       int
	Name     string
	Category string
	Price    string
}

func GetProducts(ctx context.Context, db *sql.DB, category string) ([]Product, error) {
	rows, err := db.QueryContext(ctx, "SELECT * FROM product WHERE category='"+category+"'")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var products []Product
	for rows.Next() {
		var product Product
		if err := rows.Scan(&product.Id, &product.Name, &product.Category, &product.Price); err != nil {
			return nil, err
		}jY‰
1file:///tmp/wspc/go-dvwa/vulnerable/open.go:13-13G304%Potential file inclusion via variable 0:812: 	// restricted.
13: 	return os.Open(filepath)
14: }
BunknownR%:9e858968-7fa7-44b4-9da6-960907c3db38bê
package vulnerable

import "os"

func Open(filepath string) (*os.File, error) {
	// Nothing special is needed to make Open vulnerable to local file inclusion
	// (LFi). LFi is actually possible when the filepath is not properly
	// restricted.
	return os.Open(filepath)
}jü
/file:///tmp/wspc/go-dvwa/server/router.go:55-59G104Errors unhandled. 0:à54: 		enc := json.NewEncoder(w)
55: 		enc.Encode(struct {
56: 			Output string
57: 		}{
58: 			Output: string(output),
59: 		})
60: 	})
BunknownR%:7f02a510-9b80-4bb6-a4ba-38fc53c6fe53bè		extra := r.FormValue("extra")
		output, err := vulnerable.System(r.Context(), "ping -c1 sqreen.com"+extra)
		if err != nil {
			log.Println(err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		enc := json.NewEncoder(w)
		enc.Encode(struct {
			Output string
		}{
			Output: string(output),
		})
	})

	r.PathPrefix("/").Handler(http.FileServer(http.Dir(templateDir)))

	return r
}jøﬁ
€
0file:///tmp/wspc/go-dvwa/vulnerable/sql.go:52-52G404VUse of weak random number generator (math/rand or math/rand/v2 instead of crypto/rand) 0:?51: 			"sneaker",
52: 			rand.Intn(500))
53: 		if err != nil {
BunknownR%:d01e22b2-88b0-4873-a13b-9e3d1279af09bœ			fmt.Sprintf("secret password %d", i))
		if err != nil {
			return nil, err
		}

		_, err = db.Exec(
			"INSERT INTO product (name, category, price) VALUES (?, ?, ?)",
			fmt.Sprintf("Product %d", i),
			"sneaker",
			rand.Intn(500))
		if err != nil {
			return nil, err
		}
	}

	return db, nil
}

type Product struct {
	Id       intj“ó
î
-file:///tmp/wspc/go-dvwa/server/main.go:27-27G114GUse of net/http serve function that has no support for setting timeouts 0:Ü26: 	log.Println("Serving application on", addr)
27: 	err = http.ListenAndServe(addr, sqhttp.Middleware(router))
28: 	if err != nil {
BunknownR%:34ca912e-8df6-47f2-9bd9-7a1bd3771e81b“	if err != nil {
		log.Panic("could not get the executable filename:", err)
	}
	templateDir := filepath.Join(filepath.Dir(bin), "template")

	router := NewRouter(templateDir)

	addr := ":8080"
	log.Println("Serving application on", addr)
	err = http.ListenAndServe(addr, sqhttp.Middleware(router))
	if err != nil {
		log.Fatalln(err)
	}
}j§‚
ﬂ
0file:///tmp/wspc/go-dvwa/vulnerable/sql.go:69-69G202SQL string concatenation 0:œ68: func GetProducts(ctx context.Context, db *sql.DB, category string) ([]Product, error) {
69: 	rows, err := db.QueryContext(ctx, "SELECT * FROM product WHERE category='"+category+"'")
70: 	if err != nil {
BunknownR%:ff3580cd-5ce4-4f88-b125-e66a23dbc41abÅ
type Product struct {
	Id       int
	Name     string
	Category string
	Price    string
}

func GetProducts(ctx context.Context, db *sql.DB, category string) ([]Product, error) {
	rows, err := db.QueryContext(ctx, "SELECT * FROM product WHERE category='"+category+"'")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var products []Product
	for rows.Next() {
		var product Product
		if err := rows.Scan(&product.Id, &product.Name, &product.Category, &product.Price); err != nil {
			return nil, err
		}jYÁ
‰
1file:///tmp/wspc/go-dvwa/vulnerable/open.go:13-13G304%Potential file inclusion via variable 0:812: 	// restricted.
13: 	return os.Open(filepath)
14: }
BunknownR%:9e858968-7fa7-44b4-9da6-960907c3db38bê
package vulnerable

import "os"

func Open(filepath string) (*os.File, error) {
	// Nothing special is needed to make Open vulnerable to local file inclusion
	// (LFi). LFi is actually possible when the filepath is not properly
	// restricted.
	return os.Open(filepath)
}j¢
ü
/file:///tmp/wspc/go-dvwa/server/router.go:55-59G104Errors unhandled. 0:à54: 		enc := json.NewEncoder(w)
55: 		enc.Encode(struct {
56: 			Output string
57: 		}{
58: 			Output: string(output),
59: 		})
60: 	})
BunknownR%:7f02a510-9b80-4bb6-a4ba-38fc53c6fe53bè		extra := r.FormValue("extra")
		output, err := vulnerable.System(r.Context(), "ping -c1 sqreen.com"+extra)
		if err != nil {
			log.Println(err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		enc := json.NewEncoder(w)
		enc.Encode(struct {
			Output string
		}{
			Output: string(output),
		})
	})

	r.PathPrefix("/").Handler(http.FileServer(http.Dir(templateDir)))

	return r
}jø