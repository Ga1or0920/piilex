package main

import "fmt"

func Add(a, b int) int {
	return a + b
}

func main() {
	total := Add(3, 4)
	fmt.Println("Total:", total)
}
