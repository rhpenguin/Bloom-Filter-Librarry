/*
	Copyright (C) 2015 TETSUHARU HANADA <rhpenguine@gmail.com>
	All rights reserved.

	This library may be distributed, used, and modified under the terms of
	BSD license:

	Redistribution and use in source and binary forms, with or without
	modification, are permitted provided that the following conditions are
	met:

	1. Redistributions of source code must retain the above copyright
		 notice, this list of conditions and the following disclaimer.

	2. Redistributions in binary form must reproduce the above copyright
		 notice, this list of conditions and the following disclaimer in the
		 documentation and/or other materials provided with the distribution.

	3. Neither the name(s) of the above-listed copyright holder(s) nor the
		 names of its contributors may be used to endorse or promote products
		 derived from this software without specific prior written permission.

	THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
	"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
	LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
	A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
	OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
	SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
	LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
	DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
	THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
	(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
	OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/

/*

 	=== An example application for librhpbfltr.so ===

*/

#include <fcntl.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>

#include "rhp_bfilter.h"

#define RHP_BFLTR_EX_UID_SIZE	16

// uid: Unique ID value.
static void _rhp_gen_uid(u64* uid,u64* uid_gen,u8* uid_r)
{
  if( *uid == 0xFFFFFFFFFFFFFFFFULL ){
  	(*uid_gen)++;
  }
  (*uid)++;

  *((u64*)uid_r) = *uid_gen;
  *(((u64*)uid_r) + 1) = *uid;

	return;
}

static char _rhp_uid_str_buf[256];
static char* _rhp_uid_str(u8* value)
{
	_rhp_uid_str_buf[0] = '\0';
	snprintf(_rhp_uid_str_buf,256,
			"\"0x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\"",
			(((u8*)value)[0]), (((u8*)value)[1]),
			(((u8*)value)[2]), (((u8*)value)[3]),
			(((u8*)value)[4]), (((u8*)value)[5]),
			(((u8*)value)[6]), (((u8*)value)[7]),
			(((u8*)value)[8]), (((u8*)value)[9]),
			(((u8*)value)[10]), (((u8*)value)[11]),
			(((u8*)value)[12]), (((u8*)value)[13]),
			(((u8*)value)[14]), (((u8*)value)[15]));
	return _rhp_uid_str_buf;
}



static inline void _rhp_bloom_filter_print_dump_usr(char* d,int len)
{
  int i,j;
  char* mc = d;
  printf("addr : 0x%lx , len : %d\n",(unsigned long)d,len);
  printf("*0 *1 *2 *3 *4 *5 *6 *7 *8 *9 *A *B *C *D *E *F     0123456789ABCDEF\n");
  for( i = 0;i < len; i++ ){
    int pd;
    if( i && (i % 16) == 0 ){
      printf("    ");
      for( j = 0;j < 16; j++ ){
        if( *mc >= 33 && *mc <= 126 ){printf("%c",*mc);
        }else{printf(".");}
        mc++;
      }
      printf("\n");
    }

    pd = ((*(int *)d) & 0x000000FF);

    if( pd <= 0x0F ){printf("0");}
    printf("%x ",pd);
    d++;
  }

  {
    int k,k2;
    if( (i % 16) == 0 ){
      k = 0;
      k2 = 16;
    }else{
      k = 16 - (i % 16);
      k2 = (i % 16);
    }
    for( i = 0; i < k;i++ ){printf("   ");}
    printf("    ");
    for( j = 0;j < k2; j++ ){
      if( *mc >= 33 && *mc <= 126 ){
        printf("%c",*mc);
      }else{printf(".");
      }
      mc++;
    }
  }

  printf("\n");
}

static void _rhp_bloom_filter_dump_usr(rhp_bloom_filter* bf_ctx)
{
	printf("# _rhp_bloom_filter_dump_usr\n");
	if( bf_ctx ){

		int i;

	 	pthread_mutex_lock(&(bf_ctx->lock));

		printf("bf_ctx->max_num_of_elements: %u\n", bf_ctx->max_num_of_elements);
		printf("bf_ctx->false_ratio: %f\n", bf_ctx->false_ratio);
		printf("bf_ctx->hashes_num: %u\n", bf_ctx->hashes_num);
		printf("bf_ctx->bitmap_len: %u\n", bf_ctx->bitmap_len);
		printf("bf_ctx->bitmap_bytes_len: %u\n", bf_ctx->bitmap_bytes_len);

		printf("bf_ctx->bitmap: \n");
		_rhp_bloom_filter_print_dump_usr((char*)bf_ctx->bitmap,bf_ctx->bitmap_bytes_len);
		printf("\n");

		for( i = 0; i < bf_ctx->hashes_num; i++){
			printf("bf_ctx->salt[%d]: %u\n",i,*(bf_ctx->salts + i));
		}


		printf("\n");
		printf("bf_ctx->added_num: %u\n", bf_ctx->added_num);
		printf("bf_ctx->collision_num: %u\n", bf_ctx->collision_num);

		if( bf_ctx->file_path ){

			int ext_len = sizeof(rhp_bloom_filter_fdata) + bf_ctx->bitmap_bytes_len + (sizeof(32)*bf_ctx->hashes_num);

			printf("\n");
			printf("bf_ctx->file_path: %s\n", bf_ctx->file_path);
			printf("bf_ctx->fd: %d\n", bf_ctx->fd);

			printf("bf_ctx->fdata->magic: 0x%x\n",bf_ctx->fdata->magic);
			printf("bf_ctx->fdata->max_num_of_elements: %u\n",bf_ctx->fdata->max_num_of_elements);
			printf("bf_ctx->fdata->false_ratio: %f\n",bf_ctx->fdata->false_ratio);
			printf("bf_ctx->fdata->added_num: %u\n",bf_ctx->fdata->added_num);
			printf("bf_ctx->fdata->collision_num: %u\n",bf_ctx->fdata->collision_num);
			printf("bf_ctx->fdata: \n");
			_rhp_bloom_filter_print_dump_usr((char*)bf_ctx->fdata,ext_len);
			printf("\n");


			for( i = 0; i < bf_ctx->hashes_num; i++){
				printf("bf_ctx->bitmap_updated_idxes[%d]: %lu\n",i,*(bf_ctx->bitmap_updated_idxes + i));
			}
		}

	 	pthread_mutex_unlock(&(bf_ctx->lock));

	}else{

		printf("bf_ctx == NULL\n");
	}
}

static void* _rhp_malloc_usr(size_t size)
{
	printf("# _rhp_malloc_usr(%lu)\n",size);
	return malloc(size);
}

static void _rhp_free_usr(void *ptr)
{
	printf("# _rhp_free_usr(0x%lx)\n",(unsigned long)ptr);
	free(ptr);
}

// This MUST generate cryptographically strong random bytes.
static int _rhp_random_bytes_usr(u8* buf,size_t buf_len)
{
	int fd = -1;
	size_t c = 0;
	int err = 0;

	printf("# _rhp_random_bytes_usr(0x%lx, %lu)\n", (unsigned long)buf,buf_len);

	fd = open("/dev/urandom", O_RDONLY);
	if( fd < 0 ){
		err = -errno;
		goto error;
	}

	while(c < buf_len){

	    ssize_t n = read(fd, buf + c, buf_len - c);
	    if(n < 0){
	  		err = -errno;
	  		goto error;
	    }

	    c += n;
	}

error:
	if( fd >= 0 ){
		close(fd);
	}

	return err;
}




int main(int argc, char *argv[])
{
	u32 max_num_of_elements = 20;
	double false_ratio = 0.001;

	int i;
	rhp_bloom_filter* bf_ctx = NULL;
	u8 uid[RHP_BFLTR_EX_UID_SIZE];
	u64 _rhp_uid_gen = 0, _rhp_uid = 0;
	char* uid_str;
	u8 col_uid[RHP_BFLTR_EX_UID_SIZE];
	u8 not_col_uid[RHP_BFLTR_EX_UID_SIZE];
	u64 test_rnd;
	int ret;

	printf("\n");

	//
	// Allocate a new bloom filter.
	//
	if( argc >= 2 && !strcmp(argv[1],"ex") ){

		bf_ctx = rhp_bloom_filter_alloc_ex(
				max_num_of_elements,false_ratio,
				"./bfltr.tmp",(S_IRUSR | S_IWUSR | S_IXUSR),
				_rhp_bloom_filter_dump_usr,
				_rhp_malloc_usr,
				_rhp_free_usr,
				_rhp_random_bytes_usr,
				NULL);

	}else{

		bf_ctx = rhp_bloom_filter_alloc(max_num_of_elements,false_ratio);
	}

	if( bf_ctx ){

		printf("\n");

		//
		// Output info of the bloom filter.
		//
		printf("========== dump[1] FROM ==========\n\n");
		bf_ctx->dump(bf_ctx);
		printf("\n========== dump[1] TO ==========\n");
		printf("\n\n");

	}else{

		return -EINVAL;
	}


	bf_ctx->random_bytes((u8*)&test_rnd,sizeof(u64));
	test_rnd %= max_num_of_elements;


	for(i = 0; i < max_num_of_elements; i++ ){

		_rhp_gen_uid(&_rhp_uid,&_rhp_uid_gen,uid);
		uid_str = _rhp_uid_str(uid);

		if( i == 0 ){
			memcpy(col_uid,uid,RHP_BFLTR_EX_UID_SIZE);
		}

		//
		// Add a new element into the Bloom filter.
		//
		ret = bf_ctx->add(bf_ctx,strlen(uid_str) + 1,(u8*)uid_str);
		if( ret ){

			printf("bf_ctx->add: Uid exists or collision occurred. [%d] uid:%s\n",i,uid_str);

		}else{

			printf("bf_ctx->add: OK. [%d] uid:%s\n",i,uid_str);

			if( i == test_rnd ){
				memcpy(col_uid,uid,RHP_BFLTR_EX_UID_SIZE);
			}
		}
	}
	printf("\n");

	//
	// Output info of the bloom filter.
	//
	printf("========== dump[2] FROM ==========\n\n");
	bf_ctx->dump(bf_ctx);
	printf("\n========== dump[2] TO ==========\n");
	printf("\n\n");

	//
	// [Test:1]
	//   Check an element already added into the bloom filter.
	//
	{
		uid_str = _rhp_uid_str(col_uid);

		ret = bf_ctx->contains(bf_ctx,strlen(uid_str) + 1,(u8*)uid_str);
		if( ret ){
			printf("[Test:1] bf_ctx->contains: Uid(%s) exists.\n",uid_str);
		}else{
			printf("[Test:1] bf_ctx->contains: Uid(%s) doesn't exists.\n",uid_str);
		}
		printf("\n");
	}


	//
	// [Test:2]
	//   Check an element which isn't added into the bloom filter.
	//
	{
		_rhp_gen_uid(&_rhp_uid,&_rhp_uid_gen,uid);
		memcpy(not_col_uid,uid,RHP_BFLTR_EX_UID_SIZE);

		uid_str = _rhp_uid_str(not_col_uid);

		ret = bf_ctx->contains(bf_ctx,strlen(uid_str) + 1,(u8*)uid_str);
		if( ret ){
			printf("[Test:2] bf_ctx->contains: Uid(%s) exists.\n",uid_str);
		}else{
			printf("[Test:2] bf_ctx->contains: Uid(%s) doesn't exists.\n",uid_str);
		}
		printf("\n");
	}


	printf("\n");

	//
	// Output info of the bloom filter.
	//
	printf("========== dump[3] FROM ==========\n\n");
	bf_ctx->dump(bf_ctx);
	printf("\n========== dump[3] TO ==========\n");
	printf("\n\n");


	//
	// Free the bloom filter.
	//
	rhp_bloom_filter_free(bf_ctx);


	printf("\n");

	return EXIT_SUCCESS;
}
