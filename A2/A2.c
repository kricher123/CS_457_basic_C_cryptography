#include <stdio.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <string.h>
#include <openssl/md5.h>
#include <stdlib.h>
#include <limits.h>
#include <curl/curl.h>
#include <sys/inotify.h>
#include <unistd.h>

#define BUFSIZE 1024

void detect(DIR *d , char* path);
void detect_malware(const char *path , const char *ending);
int scanned = 0;
int corruptedSHA = 0;
int corruptedMD5 = 0;
char *bad_MD5="85578cd4404c6d586cd0ae1b36c98aca";
char *bad_SHA="d56d67f2c43411d966525b3250bfaa1a85db34bf371468df1b6a9882fee78849";
void scan(DIR *d , char *path);
void scan_entry(const char *path);
FILE *openfile( const char *dirname, struct dirent *dir, const char *mode );
void monitor(DIR *d , char* path);
int count=0;
DIR *directories[1024];
//www.google.com
void main(int argc , char* argv[]){
	//DIR *temp = opendir("./Target/libappmenu-gtk-module.so");
	//return;
	char *path=realpath(argv[2],NULL);
	DIR *d;
	d = opendir(path);
	if(!strcmp(argv[1],"scan")){
		scan(d , argv[2]);
	}
	if(!strcmp(argv[1],"detect")){
		detect(d , argv[2]);
	}
	if(!strcmp(argv[1],"monitor")){
		monitor(d , argv[2]);
	}
}

void monitor(DIR *d , char* path){
	int notify_id , watchfd ; 
	struct inotify_event  *event;
	notify_id = inotify_init();
	int n;
	char eventbuf[BUFSIZE];
	char *watchname;
	char *watchednames[100];
	int max=1;
	char* p;
	
	struct dirent* dir;
	dir = readdir(d);
	dir = readdir(d);
	while ((dir = readdir(d)) != NULL) {
		char * tempstr = strdup(path);
		strcat(tempstr,"/");
		strcat(tempstr,dir->d_name);
		watchname=strdup(dir->d_name);
		watchednames[max]=strdup(dir->d_name);
		printf("added file %s to watchlist\n",watchednames[max]);
		max++;
		watchfd=inotify_add_watch(notify_id , tempstr , IN_MODIFY | IN_DELETE );
	}
	
	while(1){
		n = read(notify_id , eventbuf , BUFSIZE);
		for(p=eventbuf; p<(eventbuf+n);){
			
			event = (struct inotify_event *)p;
			p+= sizeof(struct inotify_event)+event->len;
			if(event->mask && IN_OPEN)		printf("%s was opened\n", watchednames[event->wd]);
			if(event->mask && IN_MODIFY){
				
				printf("%s was modified\n", watchednames[event->wd]);
			}
			if(event->mask && IN_DELETE)	printf("%s was deleted\n", watchednames[event->wd]);
		}
	}
}



void scan(DIR *d , char* path){
	struct dirent* dir;
	while ((dir = readdir(d)) != NULL) {
		switch(dir->d_type){
			case DT_DIR: 		if(strcmp(dir->d_name,".")&&strcmp(dir->d_name,"..")){
									//printf("%s\n",dir->d_name);
									//DIR *tempdir = opendir(dir->d_name);								
									char *tempstr;
									//printf("TEST\n");
									tempstr = strdup(path);
									//printf("TEST\n");
									strcat(tempstr,"/");
									//printf("TEST\n");
									strcat(tempstr,dir->d_name);
									//printf("TEST %s\n",tempstr);
									directories[count] = opendir(tempstr);
									count++;
									//printf("TEST\n");
									scan(directories[count-1] , tempstr);
								}
								break;
			case DT_REG: 		;
								char *temp;
								temp = strdup(path);
								strcat(temp,"/");
								strcat(temp,dir->d_name);
								printf("SCANNING %s\n\n",temp);
								scan_entry(temp);
								break;
			default: 			printf("GOT IN DEFAULT\n");
		}
    }
	printf("%d md5 corrupted files and %d sha corrupted files out of %d\n",corruptedMD5,corruptedSHA,scanned);
}

void detect(DIR *d , char* path){
	struct dirent* dir;
	while ((dir = readdir(d)) != NULL) {
		switch(dir->d_type){
			case DT_DIR: 		if(strcmp(dir->d_name,".")&&strcmp(dir->d_name,"..")){
									//printf("%s\n",dir->d_name);
									//DIR *tempdir = opendir(dir->d_name);								
									char *tempstr;
									//printf("TEST\n");
									tempstr = strdup(path);
									//printf("TEST\n");
									strcat(tempstr,"/");
									//printf("TEST\n");
									strcat(tempstr,dir->d_name);
									//printf("TEST %s\n",tempstr);
									directories[count] = opendir(tempstr);
									count++;
									//printf("TEST\n");
									detect(directories[count-1] , tempstr);
								}
								break;
			case DT_REG: 		;
								char *temp;
								temp = strdup(path);
								strcat(temp,"/");
								strcat(temp,dir->d_name);
								//printf("detecting %s\n\n",temp);
								detect_malware(temp , ".com");
								detect_malware(temp , ".org");
								detect_malware(temp , ".net");
								detect_malware(temp , ".int");
								detect_malware(temp , ".edu");
								detect_malware(temp , ".gov");
								detect_malware(temp , ".mil");
								break;
			default: 			printf("GOT IN DEFAULT\n");
		}
    }
	
}

void detect_malware(const char *path , const char *ending){
    FILE *fp = fopen(path, "r");
    if (fp == NULL) {
        printf("Error opening file %s\n", path);
        return;
    }
    char buffer[4096]; 
    while (fgets(buffer, sizeof(buffer), fp) != NULL) {
        char *ptr = buffer;
        while ((ptr = strstr(ptr, "www.")) != NULL) {
            char *start = ptr + 4; 
            char *end = strstr(start, ending);
            if (end != NULL) {
				char name[1024]; 
				int i=0;
				name[0]='w';
				name[1]='w';
				name[2]='w';
				name[3]='.';
				for(;i<(int)(end-start);i++){
					name[i+4]=start[i];
				}
				name[i+4]='.';
				name[i+5]=ending[1];
				name[i+6]=ending[2];
				name[i+7]=ending[3];
				name[i+8]='\0';
				/*
				CURL *curl;
				CURLcode result;
				curl = curl_easy_init();
				if(curl == NULL){
					printf("curl easy init failed\n");
				}
				
				curl_easy_setopt(curl , CURLOPT_URL , "https://cloudflare-dns.com/dns-query");
				result = curl_easy_perform(curl);
				
				if(result!= CURLE_OK){
					printf("CURL NOT OKAY\n");
				}
				*/
				char command[1024] = "curl -s -H \"accept: application/dns-json\" https://1.1.1.1/dns-query?name=" ; // HERE
				strcat(command , name);
				FILE *fpipe = popen(command, "r");
				char *output = (char *)malloc(1024*sizeof(char));
				fgets(output , 1023 , fpipe);
				//printf("OUT %s\n",output);
				char *ptr = strstr(output, "Status\":");
				int Iptr = ptr[8];
				//printf("lala\n");
				if(ptr[8]=='0'){
					printf("found address %s in file %s and its not a malware\n",name , path );
				}else{
					printf("found address %s in file %s and its potentially a malware\n",name , path );
					
				}
				//printf("%c\n",Iptr);
				fclose(fpipe);
				
                ptr = end + 4; 
            } else {
                break; 
            }
            ptr++; 
        }
    }
    fclose(fp);
}

void scan_entry(const char *path){
	scanned++;
    printf("CHECK FILE WITH PATH: %s\n", path);

    char command[1024] = "md5sum ";
    strcat(command, path);

    FILE *fpipe = popen(command, "r");
    if (fpipe == NULL) {
		perror("popen");
        printf("Failed to run %s\n", command);
        return;
    }
	char *output = (char *)malloc(34*sizeof(char));
	fgets(output , 33 , fpipe);
	fclose(fpipe);
	//printf("%s\n",output);
	//output="85578cd4404c6d586cd0ae1b36c98aca";
	if(!strcmp(output,bad_MD5)){
		corruptedMD5++;
		printf("FILE GOT THE MD5 HASH OF THE ATTACKER\n");
	}else{
		printf("FILE IS CLEAN FOR MD5\n");
	}
	char command2[1024] = "sha256sum ";
	strcat(command2,path);
	fpipe = popen(command , "r");
	char output2[1024];
	fgets(output2 , 33 , fpipe);
	fclose(fpipe);
	if(!strcmp(output,bad_SHA)){
		corruptedSHA++;
		printf("FILE GOT THE SHA HASH OF THE ATTACKER\n\n");
	}else{
		printf("FILE IS CLEAN FOR SHA\n\n");
	}
}

