/* base64 encoder/decoder based on public domain implementation
 * by Chris Venter */

#include <arpa/inet.h>
#include <stdlib.h>

#include <rpm/rpmbase64.h>


static char base64_encode_value(char value_in)
{
	static const char encoding[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	if (value_in > 63) return '=';
	return encoding[(int)value_in];
}

static char *base64_encode_block(const char *plaintext_in, int length_in, char *codechar)
{
	const char *plainchar = plaintext_in;
	const char *const plaintextend = plaintext_in + length_in;
	char result;
	char fragment;
	
	while (1) {
		if (plainchar == plaintextend) {
			return codechar;
		}
		fragment = *plainchar++;
		result = (fragment & 0x0fc) >> 2;
		*codechar++ = base64_encode_value(result);
		result = (fragment & 0x003) << 4;
		if (plainchar == plaintextend)
		{
			*codechar++ = base64_encode_value(result);
			*codechar++ = '=';
			*codechar++ = '=';
			return codechar;
		}
		fragment = *plainchar++;
		result |= (fragment & 0x0f0) >> 4;
		*codechar++ = base64_encode_value(result);
		result = (fragment & 0x00f) << 2;
		if (plainchar == plaintextend)
		{
			*codechar++ = base64_encode_value(result);
			*codechar++ = '=';
			return codechar;
		}
		fragment = *plainchar++;
		result |= (fragment & 0x0c0) >> 6;
		*codechar++ = base64_encode_value(result);
		result  = (fragment & 0x03f) >> 0;
		*codechar++ = base64_encode_value(result);
	}
	/* control should not reach here */
	return codechar;
}

#define BASE64_DEFAULT_LINE_LENGTH 64

char *rpmBase64Encode(const void *data, size_t len, int linelen)
{
	size_t encodedlen;
	const char *dataptr = (const char *)data;
	char *output;
	char *outptr;
	
	if (data == NULL)
		return NULL;

	if (linelen < 0)
		linelen = BASE64_DEFAULT_LINE_LENGTH;

	linelen /= 4;
	encodedlen = ((len + 2) / 3) * 4;
	if (linelen > 0) {
		encodedlen += encodedlen/(linelen * 4) + 1;
	}
	++encodedlen; /* for zero termination */

	output = (char *)malloc(encodedlen);
	if (output == NULL)
		return NULL;
		
	outptr = output;	
	while (len > 0) {
		if (linelen > 0 && len > linelen * 3) {
			outptr = base64_encode_block(dataptr, linelen * 3, outptr);
			len -= linelen * 3;
			dataptr += linelen * 3;
		} else {
			outptr = base64_encode_block(dataptr, len, outptr);
			len = 0;
		}
		if (linelen > 0) {
			*outptr++ = '\n';
		}
	}
	*outptr = '\0';
	return output;
}

static int base64_decode_value(unsigned char value_in)
{
	static const int decoding[] = {62,-1,-1,-1,63,52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-2,-1,-1,-1,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,-1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51};
	value_in -= 43;
	if (value_in >= sizeof(decoding)/sizeof(int))
		return -1;
	return decoding[value_in];
}

static size_t base64_decode_block(const char *code_in, const size_t length_in, char *plaintext_out)
{
	const char *codechar = code_in;
	char *plainchar = plaintext_out;
	int fragment;
	
	*plainchar = 0;
	
	while (1)
	{
		do {
			if (codechar == code_in+length_in)
			{
				return plainchar - plaintext_out;
			}
			fragment = base64_decode_value(*codechar++);
		} while (fragment < 0);
		*plainchar    = (char)((fragment & 0x03f) << 2);

		do {
			if (codechar == code_in+length_in)
			{
				return plainchar - plaintext_out;
			}
			fragment = base64_decode_value(*codechar++);
		} while (fragment < 0);
		*plainchar++ |= (char)((fragment & 0x030) >> 4);
		*plainchar    = (char)((fragment & 0x00f) << 4);

		do {
			if (codechar == code_in+length_in)
			{
				return plainchar - plaintext_out;
			}
			fragment = base64_decode_value(*codechar++);
		} while (fragment < 0);
		*plainchar++ |= (char)((fragment & 0x03c) >> 2);
		*plainchar    = (char)((fragment & 0x003) << 6);

		do {
			if (codechar == code_in+length_in)
			{
				return plainchar - plaintext_out;
			}
			fragment = base64_decode_value(*codechar++);
		} while (fragment < 0);
		*plainchar++   |= (char)(fragment & 0x03f);
	}
	/* control should not reach here */
	return plainchar - plaintext_out;
}

int rpmBase64Decode(const char *in, void **out, size_t *outlen)
{
	size_t outcnt = 0;
	const char *inptr = in;

	*out = NULL;

	if (in == NULL) {
		return 1;
	}
	
	while (*inptr != '\0') {
		/* assume all ASCII control chars as whitespace */
		if (*inptr > 32) {
			if (base64_decode_value(*inptr) != -1) {
				++outcnt;
			} else {
				return 3;
			}
		}
		++inptr;
	}
	
	if (outcnt % 4 != 0)
		return 2;
	
	outcnt = (outcnt / 4) * 3;
	
	*out = (char *)malloc(outcnt + 1); /* base64_decode_block can write one extra character */
	
	if (*out == NULL)
		return 4;
	
	*outlen = base64_decode_block(in, inptr - in, (char *)*out);

	return 0;
}

#define CRC24_INIT 0xb704ce
#define CRC24_POLY 0x1864cfb

char *rpmBase64CRC(const unsigned char *data, size_t len)
{
	uint32_t crc = CRC24_INIT;
	int i;

	while (len--) {
		crc ^= (*data++) << 16;
		for (i = 0; i < 8; i++) {
			crc <<= 1;
			if (crc & 0x1000000)
				crc ^= CRC24_POLY;
		}
	}
	crc = htonl(crc & 0xffffff);
	data = (unsigned char *)&crc;
	++data;
	return rpmBase64Encode(data, 3, 0);
}

#ifdef BASE64_TEST
#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[]) 
{
	static char tst[]="wtrt8122čLýáj\x20s ~ýhž\t4\x02šjjmBvž^%$RTš#á.íěj\x1hčýčŤc+";
	char *encoded;
	void *decoded;
	size_t size;
	int err;
	printf("Original: %lu\n%s\n", sizeof(tst)-1, tst);
	encoded = rpmBase64Encode(tst, sizeof(tst)-1, 64);
	printf("Encoded: %lu\n%s\n", strlen(encoded), encoded);
	if ((err = rpmBase64Decode(encoded, &decoded, &size)) != 0) {
		fprintf(stderr, "Error in decode: %d\n", err);
		return 1;
	}
	printf("Decoded:\n%.*s\n", (int)size, (char *)decoded);
	if (size != sizeof(tst)-1) {
		fprintf(stderr, "Size differs orig: %lu new: %lu\n", sizeof(tst)-1, size);
		return 1;
	}
	if (memcmp(tst, decoded, size) != 0) {
		fprintf(stderr, "Decoded data differs.\n");
		return 1;
	}
	fprintf(stderr, "OK\n");
	return 0;
}
#endif

