#ifndef INGEST_MD5_H
#define INGEST_MD5_H

/* Read in 1024 bytes at a time from the file while you are loading up the 
 * memory before getting the checksum for it.
 */
#define READSIZE 1024

#define _GNU_SOURCE

/* Return a hex string representing the MD5 digest of whatever bytes starting 
 * at *input  and ending at (*input + in_len).  The return string is NULL 
 * terminated, but we are still going to stick the length of the string in
 * *out_len.
 */ 
char *compute_md5(char *input, unsigned int in_len, int *out_len);


/* Accept a previously opened file and a pointer to an integer that will carry 
 * back the number of bytes read from the file.  Return a pointer to a blob of 
 * data that contains all of the bytes from the file.  Remember to free this
 * memory when you are done with it.
 */
unsigned char *read_file(FILE *f, int *f_len);


/* Very much a wrapper for read_file, and compute_md5.  It accepts a pointer 
 * to a previously opened file which it sends off to read_file to get loaded
 * into a blob of memory.  It then sends the blob of memory and the blob's 
 * length to compute_md5 where it generates the MD5 checksum which is always
 * 32 hex characters. If you factor out this routine, make sure you free the
 * memory associated with the blob.
 */
unsigned char *process_file(FILE *f, unsigned int *hash_len);


/* Accepts the fully qualified name which should be where the program can find
 * the file to do the MD5 sum against.  Assuming it can open the file at the 
 * location specified by *FQN, it opens the file and sends the file pointer 
 * off to process_file which sends back the MD5 sum.   
 */
int process_file_by_name(char *FQN, char *buf, int buf_len );

#endif
