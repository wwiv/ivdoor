package dos

import (
	"fmt"

	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"
)

func Int20(mu uc.Unicorn, intrNum uint32) error {
	fmt.Println("Int20: Stop")
	mu.Stop()
	return nil
}
