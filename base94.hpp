#pragma once

#ifndef _BASE94_HPP_
#define _BASE94_HPP_

#include <stdint.h>
#include <vector>
#include <string>

class base94
{
	/* 96 printable characters(include tab)	*/
	/* remove space and tab for uniformity	*/
	/* luckly, 11/9 > log(256)/log(94)		*/
protected:
	enum {
		BASE94_SYMBOL_COUNT = 94,
		BASE94_INPUT_BLOCK_SIZE = 9,
		BASE94_OUTPUT_BLOCK_SIZE = 11,
	};
	static constexpr char encode_table[BASE94_SYMBOL_COUNT+1] = {
		"!\"#$%&'()*+,-./"
		"0123456789"
		":;<=>?@"
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"[\\]^_`"
		"abcdefghijklmnopqrstuvwxyz"
		"{|}~"
	};

	static constexpr char first_symbol = encode_table[0];
	static constexpr char last_symbol = encode_table[BASE94_SYMBOL_COUNT - 1];

	static constexpr uint32_t encode_tail_cut[BASE94_INPUT_BLOCK_SIZE] = {
	//	0,1,2,3,4,5,6,7, 8	input_tail
	//	0,2,3,4,5,7,8,9,10	ceil(input_tail*8/log2(94))
	    0,9,8,7,6,4,3,2, 1	//11-ceil(input_tail*8/log2(94))
	};
	static constexpr uint32_t decode_tail_cut[BASE94_OUTPUT_BLOCK_SIZE] = {
	//	0,1,2,3,4,5,6,7,8,9,10	output_tail
	//	0,X,1,2,3,4,X,5,6,7, 8	inverse to input_tail, 1 and 6 is invalid
		0,0,8,7,6,5,0,4,3,2, 1	//9-input_tail
	};

	typedef unsigned char base94_input_block[BASE94_INPUT_BLOCK_SIZE];
	typedef char base94_output_block[BASE94_OUTPUT_BLOCK_SIZE];

	inline static bool encode_symbol(uint32_t x, char& y) {
		y = encode_table[x];
		return true;
	}

	inline static bool decode_symbol(char x, uint32_t& y) {
		if (x < first_symbol || x > last_symbol)
			return false;
		y = x - first_symbol;
		return true;
	}

	static bool encode_block(const base94_input_block& x, base94_output_block& y) {
		enum {
			BASE94_ENCODE_MOD = (1 << 24) % BASE94_SYMBOL_COUNT,
			BASE94_ENCODE_MOD2 = (BASE94_ENCODE_MOD * BASE94_ENCODE_MOD) % BASE94_SYMBOL_COUNT,
		};
		uint32_t a = (x[0] << 16) | (x[1] << 8) | x[2];
		uint32_t b = (x[3] << 16) | (x[4] << 8) | x[5];
		uint32_t c = (x[6] << 16) | (x[7] << 8) | x[8];
		uint32_t d = 0;
		//x = a*2^48 + b*2^24 + c
		for (uint32_t i = BASE94_OUTPUT_BLOCK_SIZE - 1; i != -1; i--) {
			d = (a * BASE94_ENCODE_MOD2 + b * BASE94_ENCODE_MOD + c) % BASE94_SYMBOL_COUNT;
			if (!encode_symbol(d, y[i]))
				return false;
			b += a % BASE94_SYMBOL_COUNT << 24;
			c += b % BASE94_SYMBOL_COUNT << 24;
			a /= BASE94_SYMBOL_COUNT;
			b /= BASE94_SYMBOL_COUNT;
			c /= BASE94_SYMBOL_COUNT;
		}
		return true;
	}
	static bool decode_block(const base94_output_block& x, base94_input_block& y) {
		enum {
			BASE94_DECODE_MASK = (1 << 24) - 1,
		};
		uint32_t a = 0;
		uint32_t b = 0;
		uint32_t c = 0;
		uint32_t d = 0;
		for (uint32_t i = 0; i < BASE94_OUTPUT_BLOCK_SIZE; i++) {
			if (!decode_symbol(x[i], d))
				return false;
			c *= BASE94_SYMBOL_COUNT;
			b *= BASE94_SYMBOL_COUNT;
			a *= BASE94_SYMBOL_COUNT;
			c += d;
			b += c >> 24;
			a += b >> 24;
			c &= BASE94_DECODE_MASK;
			b &= BASE94_DECODE_MASK;
		}
		y[0] = a >> 16; y[1] = a >> 8; y[2] = a;
		y[3] = b >> 16; y[4] = b >> 8; y[5] = b;
		y[6] = c >> 16; y[7] = c >> 8; y[8] = c;
		return true;
	}
public:
	static bool encode(const std::string& /*in*/p, std::string& /*out*/c) {
		uint32_t block_count = (p.size() + BASE94_INPUT_BLOCK_SIZE - 1) / BASE94_INPUT_BLOCK_SIZE;
		uint32_t buffer_size = block_count * BASE94_OUTPUT_BLOCK_SIZE;
		uint32_t tail = p.size() % BASE94_INPUT_BLOCK_SIZE;
		std::string t;
		t.resize(buffer_size);
		uint32_t off_v = 0, off_s = 0;
		for (; off_v + BASE94_INPUT_BLOCK_SIZE <= p.size(); off_v += BASE94_INPUT_BLOCK_SIZE, off_s += BASE94_OUTPUT_BLOCK_SIZE) {
			if (!encode_block(*(base94_input_block*)(p.data() + off_v), *(base94_output_block*)(t.data() + off_s)))
				return false;
		}
		if (tail > 0) {
			base94_input_block buff = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
			for (uint32_t i = 0; i < tail; i++)
				buff[i] = p[off_v + i];
			if (!encode_block(buff, *(base94_output_block*)(t.data() + off_s)))
				return false;
			t.resize(buffer_size - encode_tail_cut[tail]);
		}
		c = std::move(t);
		return true;
	}
	static bool decode(const std::string& /*in*/c, std::string& /*out*/p) {
		uint32_t block_count = (c.size() + BASE94_OUTPUT_BLOCK_SIZE - 1) / BASE94_OUTPUT_BLOCK_SIZE;
		uint32_t buffer_size = block_count * BASE94_INPUT_BLOCK_SIZE;
		uint32_t tail = c.size() % BASE94_OUTPUT_BLOCK_SIZE;

		if (tail > 0 && decode_tail_cut[tail] == 0)
			return false;

		std::string t;
		t.resize(buffer_size);
		uint32_t off_s = 0, off_v = 0;
		for (; off_s + BASE94_OUTPUT_BLOCK_SIZE <= c.size(); off_s += BASE94_OUTPUT_BLOCK_SIZE, off_v += BASE94_INPUT_BLOCK_SIZE) {
			if (!decode_block(*(base94_output_block*)(c.data() + off_s), *(base94_input_block*)(t.data() + off_v)))
				return false;
		}
		if (tail > 0) {
			base94_output_block buff = { first_symbol, first_symbol, first_symbol, first_symbol, first_symbol,
				first_symbol, first_symbol, first_symbol, first_symbol, first_symbol, first_symbol };
			for (uint32_t i = 0; i < tail; i++)
				buff[i] = c[off_s + i];
			if (!decode_block(buff, *(base94_input_block*)(t.data() + off_v)))
				return false;
			t.resize(buffer_size - decode_tail_cut[tail]);
		}
		p = std::move(t);
		return true;
	}
};


#endif