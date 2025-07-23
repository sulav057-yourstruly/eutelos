package main

import (
  "log"
  "net/http"
)

func main() {
  http.HandleFunc("/", HelloHandler)
  log.Println("Server started on http://localhost:8080")
  log.Fatal(http.ListenAndServe(":8080", nil))
}
