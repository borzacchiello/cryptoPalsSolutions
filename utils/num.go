package utils

func Abs[T float32 | float64 | int](a T) T {
	if a < 0 {
		return -a
	}
	return a
}

func Min[T float32 | float64 | int](a, b T) T {
	if a < b {
		return a
	}
	return b
}
