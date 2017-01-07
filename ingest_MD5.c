#include <dirent.h>
#include <libgen.h>
#include <openssl/evp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

char *compute_md5(char *input, unsigned int in_len, int *out_len){
   const EVP_MD *m;
   EVP_MD_CTX ctx;
   unsigned char *ret, *human,  hex[3], *incr;
   int human_size = 2*EVP_MAX_MD_SIZE + 1;
   int i;
   OpenSSL_add_all_digests();
   if(!(m=EVP_get_digestbyname("md5"))){
      return NULL;
   }
   if(!(ret = (unsigned char*)malloc(EVP_MAX_MD_SIZE))){
      return NULL;
   }
   if(!(human = (unsigned char*)malloc(human_size))){
      return NULL;
   }
   EVP_DigestInit(&ctx, m);
   EVP_DigestUpdate(&ctx, input, in_len); 
   EVP_DigestFinal(&ctx, ret, out_len); 
   memset(human, 0, 2*EVP_MAX_MD_SIZE + 1);
   incr = ret;
   for(i = 0; i < *out_len; i++){
      snprintf(hex, 3, "%02x", *incr); 
      strncat(human, hex, 2);
      incr++;
   }
   return human;
}

unsigned char *read_file(FILE *f, int *f_len){
   unsigned char *current_buf = NULL, *last_buf = NULL; 
   unsigned char inbuf[READSIZE];
   int previously_read, this_read;
   
   previously_read = 0;
   for(;;){
      // Attempt to read in 1*READSIZE from the file pointer into inbuf.
      this_read = fread(inbuf, sizeof(unsigned char), READSIZE, f);
      if(this_read > 0){
         // We got something.  Move the buffer pointers.
         last_buf = current_buf;
       
         // Create a new buffer big enough to handle everything we have read 
         // so far and what we read with the last fread. 
         current_buf = (unsigned char *)malloc(previously_read + this_read);

         // Copy the old bytes into the new buffer.
         memcpy(current_buf, last_buf, previously_read);

         // Now copy in the bytes from this read.
         memcpy(&current_buf[previously_read], inbuf, this_read);

         // We don't need last_buf anymore.
         if(last_buf)
            free(last_buf);

         // Account for the new bytes we just read.
         previously_read += this_read;

         // Anything more to read from the file?
         if(feof(f) > 0){
            // We are at the end-of-file.  Return the buffer and the 
            // number of bytes we read from the file.  This marks your 
            // standard exit. 
            *f_len = previously_read;
            return current_buf;
         }
      } else {
         // Something is wrong, we didn't read anything from the file.
         if(current_buf)
            free(current_buf);
         break;
      }
   }
   *f_len = 0;
   return NULL;
}

unsigned char *process_file(FILE *f, unsigned int *hash_len){
   int blob_len;
   unsigned char *blob, *md5sum;
   blob = read_file(f, &blob_len);
   if(blob){
      md5sum = compute_md5(blob, blob_len, hash_len);
      free(blob);
      return md5sum;
   } else {
     *hash_len = 0;
     return NULL;
   }
}

int process_file_by_name(char *FQN, char *buf, int buf_len ){
   static unsigned char *md5_sum = NULL; 
   unsigned int hash_len;
   FILE *f = fopen(FQN, "rb");
   if(!f){
      perror(FQN);
      return 1;
   }
   md5_sum = process_file(f, &hash_len);
   fclose(f);
   if(!md5_sum){
      perror(FQN);
      return 1;
   }
   strncpy(buf, md5_sum, buf_len);
   return 0;
}
