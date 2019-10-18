#include "cela_rand.h"

#include <stdlib.h>
#include <time.h>

#include "sha2.h"

void cela_rand(unsigned char *buf, int len)
{
	unsigned char tmp[32];
	sha256_context ctx;
	int i, r, m;

	for (i = 0; i < 32; i++)
		tmp[i] = (unsigned char)rand();

	r = 0;
	while (r < len)
	{
		sha256_starts(&ctx);
		sha256_update(&ctx, tmp, 32);
		sha256_finish(&ctx, tmp);

		m = ((len - r) < 32) ? (len - r) : 32;
		for (i = 0; i < m; i++)
			buf[r++] = tmp[i];
	}
}