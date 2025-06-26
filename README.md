# base94
extend base64/base85

	96 printable characters(include tab)
	remove space and tab for uniformity
	luckly, 11/9 > log(256)/log(94)
	so, this algorithm transform 9 bytes to 11 bytes
