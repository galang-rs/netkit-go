package browser

// Common screen sizes for fingerprint diversity
var ScreenSizes = [][2]int{
	{1920, 1080},
	{1366, 768},
	{1440, 900},
	{1536, 864},
	{1280, 720},
	{2560, 1440},
	{1600, 900},
	{1680, 1050},
	{2560, 1600},
	{3840, 2160},
}

// Heap size limits for fingerprint diversity
var HeapSizeLimits = []int{
	4294705152, // 16 cores
	2147483648, // 8 cores
	1073741824, // 4 cores
	536870912,  // 2 cores
}

// HeapToConcurrency maps heap size to hardware concurrency
var HeapToConcurrency = map[int]int{
	4294705152: 16,
	2147483648: 8,
	1073741824: 4,
	536870912:  2,
}
