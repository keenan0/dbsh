//gcc main.c -o dbsh -lcurl -lcjson && ./dbsh

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/wait.h>
#include <ctype.h>
#include <curl/curl.h>
#include <cjson/cJSON.h>
#include <stdbool.h>

#define BUFFER_SIZE 4096
#define MAX_LINE_LENGTH 256
#define MAX_URL_LENGTH 1024
#define MAX_AUTH_LENGTH 512
#define MAX_JSON_LENGH 16384

#define YELLOW_BOLD "\033[1;33m"
#define GREEN_BOLD "\033[0;32m"
#define RED "\033[1;31m"
#define RESET "\033[0m"

#define DBSH_RL_BUFSIZE 1024
#define DBSH_TOK_BUFSIZE 64
#define DBSH_TOK_DELIM " \t\r\n\a"

char DEFAULT_LOCAL_PATH[] = "/home/claudiu/dbsh/";

struct user_data {
    char auth_code[MAX_AUTH_LENGTH];
    char auth_token[BUFFER_SIZE];
    char token_type[MAX_LINE_LENGTH];
    char account_id[MAX_AUTH_LENGTH];
    char user_id[MAX_AUTH_LENGTH];
    char username[MAX_AUTH_LENGTH];
};

struct response {
    char* memory;
    size_t size;
    FILE* fp;
};

struct user_data user;
char api_key[MAX_LINE_LENGTH]    = {0};
char api_secret[MAX_LINE_LENGTH] = {0};

int dbsh_put(char** args);
int dbsh_rm(char** args);
int dbsh_mkdir(char** args);
int dbsh_cp(char** args);
int dbsh_mv(char** args);
int dbsh_get(char** args);
int dbsh_ls(char** args);
int dbsh_cd(char **args);
int dbsh_help(char **args);
int dbsh_exit(char **args);

static size_t write_callback(void *ptr, size_t size, size_t nmemb, char *data) {
    size_t total_size = size * nmemb;
    if (total_size < BUFFER_SIZE - strlen(data) - 1) {
        strncat(data, (char*)ptr, total_size);
    }
    return total_size;
}

static size_t write_callback_16k(void *ptr, size_t size, size_t nmemb, char *data) {
    size_t total_size = size * nmemb;
    size_t current_size = strlen(data);

    if (current_size + total_size + 1 > MAX_JSON_LENGH) {
        data = realloc(data, current_size + total_size + 1);
        if (data == NULL) {
            perror("Error reallocating memory\n");
            exit(EXIT_FAILURE);
        }
    }
    
    memcpy(data + current_size, ptr, total_size);
    data[current_size + total_size] = '\0';

    return total_size;
}

static size_t write_callback_file(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    struct response *mem = (struct response *)userp;

    char *ptr = (char*)realloc(mem->memory, mem->size + realsize + 1);
    if(!ptr) {
        printf("not enough memory (realloc returned NULL)\n");
        return 0;
    }
    printf("  " YELLOW_BOLD "(*)" RESET "  Retrieved %ld bytes\n", realsize);
    size_t written = fwrite(contents, size, nmemb, mem->fp);

    mem->memory = ptr;
    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;

    return realsize;
}

char *builtin_str[] = {
    "put",
    "rm",
    "mkdir",
    "cp",
    "mv",
    "get",
    "ls",
    "cd",
    "help",
    "q"
};

char *builtin_str_help[] = {
    GREEN_BOLD "put <save_path> <file_path>" RESET ": uploads the file from the <file_path> to dropbox at <save_path>"

    GREEN_BOLD "rm <path>" RESET ": removes the specified path (file/folder)",

    GREEN_BOLD "mkdir <path>" RESET ": make a new directory at the path specified",

    GREEN_BOLD "cp <src> <dest>" RESET ": copy a file from <src> to <dest> (src/dest are paths to files in the dropbox)",

    GREEN_BOLD "mv <src> <dest>" RESET ": moves a file from <src> to <dest> (src/dest are paths to files in the dropbox)",
    
    GREEN_BOLD "get <download_file> [local_path]" RESET ": save the file in the current local directory",

    GREEN_BOLD "ls [file_name] [-r] [-f]"RESET": -r stands for recursive list | -f will show just the files",

    "cd dir_name: change local directory",

    GREEN_BOLD "help " RESET ": shows a list of all the available functions",

    GREEN_BOLD "q " RESET ": quit the shell"
};

int (*builtin_func[]) (char **) = {
    &dbsh_put,
    &dbsh_rm,
    &dbsh_mkdir,
    &dbsh_cp,
    &dbsh_mv,
    &dbsh_get,
    &dbsh_ls,
    &dbsh_cd,
    &dbsh_help,
    &dbsh_exit
};

int dbsh_num_builtins() { return sizeof(builtin_str) / sizeof(char *); }

char* extract_file_name(char* PATH) {
    const char *last_slash = strrchr(PATH, '/');

    if (last_slash == NULL) {
        return strdup(PATH);
    } else {
        return strdup(last_slash + 1);
    }
}

char* concat(const char* str1, const char* str2) {
    size_t len1 = strlen(str1);
    size_t len2 = strlen(str2);

    char* result = (char*)malloc(len1 + len2 + 1);  
    if (result == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }

    strcpy(result, str1);
    strcat(result, str2);

    return result;
}

void download_file(struct user_data user, char* PATH, char* LOCAL_PATH) {
    CURL *curl;
    CURLcode res;
    FILE* fp;

    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();

    char* file_name = extract_file_name(PATH);
    char* local = concat(LOCAL_PATH, file_name);

    printf(RED "Downloading %s as %s...\n" RESET, PATH, local);

    if (curl) {
        fp = fopen(local, "wb");
        if (fp == NULL) {
            perror("Error opening file for writing");
            return;
        }

        struct response chunk;
        chunk.memory = (char*)malloc(1); 
        chunk.size = 0;
        chunk.fp = fp;

        curl_easy_setopt(curl, CURLOPT_URL, "https://content.dropboxapi.com/2/files/download");

        cJSON *arg_json = cJSON_CreateObject();
        cJSON_AddStringToObject(arg_json, "path", PATH);
        char *json_str = cJSON_PrintUnformatted(arg_json);

        struct curl_slist *headers = NULL;
        char auth_header[BUFFER_SIZE];
        snprintf(auth_header, sizeof(auth_header) + 24, "Authorization: Bearer %s", user.auth_token);
        headers = curl_slist_append(headers, auth_header);

        char dropbox_api_header[BUFFER_SIZE];
        snprintf(dropbox_api_header, sizeof(dropbox_api_header), "Dropbox-API-Arg: %s", json_str);
        headers = curl_slist_append(headers, dropbox_api_header);

        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback_file);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)&chunk);

        res = curl_easy_perform(curl);

        if (res != CURLE_OK) {
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        } else {
            printf(RED "Download completed at: %s\n" RESET, local);
        }

        fclose(fp);
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        cJSON_Delete(arg_json);
        free(json_str);
    }

    curl_global_cleanup();
}

char* get_ls(struct user_data user, const char* PATH, bool FLAG_ALL, bool FILES_ONLY) {
    CURL *curl;
    CURLcode res;

    cJSON *root = cJSON_CreateObject();
    cJSON_AddBoolToObject(root, "include_deleted", 0);
    cJSON_AddBoolToObject(root, "include_has_explicit_shared_members", 0);
    cJSON_AddBoolToObject(root, "include_media_info", 0);
    cJSON_AddBoolToObject(root, "include_mounted_folders", (FILES_ONLY ? 0 : 1));
    cJSON_AddBoolToObject(root, "include_non_downloadable_files", 1);
    cJSON_AddStringToObject(root, "path", PATH);
    cJSON_AddBoolToObject(root, "recursive", (FLAG_ALL ? 1 : 0));

    char *data = cJSON_PrintUnformatted(root);

    char* response_json = (char*)malloc(sizeof(char) * MAX_JSON_LENGH);
    if(response_json == NULL) {
        perror(" Could not initialise pointer.\n");
        exit(EXIT_FAILURE);
    }
    response_json[0] = 0;

    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();

    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "https://api.dropboxapi.com/2/files/list_folder");

        struct curl_slist *headers = NULL;
        char auth_header[BUFFER_SIZE];
        snprintf(auth_header, sizeof(auth_header) + 24, "Authorization: Bearer %s", user.auth_token);
        headers = curl_slist_append(headers, auth_header);
        headers = curl_slist_append(headers, "Content-Type: application/json");
        
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback_16k);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, response_json);

        res = curl_easy_perform(curl);

        if (res != CURLE_OK) {
            fprintf(stderr, "CURL failed: %s\n", curl_easy_strerror(res));
        }

        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
    }

    curl_global_cleanup();

    return response_json;
}

void print_files(char* json_res, bool FILES_ONLY) {
    cJSON *root = cJSON_Parse(json_res);
    if (root == NULL) {
        perror(" Error parsing JSON\n");
        return;
    }

    cJSON *entries = cJSON_GetObjectItem(root, "entries");
    if (entries == NULL) {
        perror(" No entries found in the JSON response\n");
        cJSON_Delete(root);
        return;
    }

    int num_entries = cJSON_GetArraySize(entries);
    for (int i = 0; i < num_entries; i++) {
        cJSON *entry = cJSON_GetArrayItem(entries, i);
        if (entry == NULL) {
            continue;
        }

        cJSON *path_display = cJSON_GetObjectItem(entry, "path_display");
        if (path_display != NULL && cJSON_IsString(path_display)) {
            if(FILES_ONLY) {
                cJSON *tag = cJSON_GetObjectItem(entry, ".tag");
                if (tag != NULL && cJSON_IsString(tag) && strcmp(tag->valuestring, "folder") != 0) {
                    printf("    \033[1;33m%s\033[0m\n", path_display->valuestring);
                }
            } else {
                printf("    \033[1;33m%s\033[0m\n", path_display->valuestring);
            }
        }
        
    }

    cJSON_Delete(root);
}

int dbsh_get(char** args) {
    if(args[1] == NULL) {
        perror("Usage: get <file_name> [local_path]\n");
        return 1;
    } else if(args[2] == NULL) {
        download_file(user, args[1], DEFAULT_LOCAL_PATH);
    } else {
        download_file(user, args[1], args[2]);
    }

    return 1;
}

int dbsh_ls(char** args) {
    char* ls_response = (char*)malloc(sizeof(char) * MAX_JSON_LENGH);
    bool files_only = false;

    if(args[1] == NULL) {
        // List just the root files
        //printf("%s\n", get_ls(user, "", false));
        ls_response = get_ls(user, "", false, false);
    } else if(strcmp(args[1], "-r") == 0) {
        // Recursive list all
        //printf("%s\n", get_ls(user, "", true));
        ls_response = get_ls(user, "", true, false);
    } else if(strcmp(args[1], "-f") == 0) {
        files_only = true;
        ls_response = get_ls(user, "", true, false);
    }
    else {
        // ls for a given path
        //printf("%s\n", get_ls(user, args[1], true));
        if(args[2] == NULL) {
            ls_response = get_ls(user, args[1], false, false);
        } else if(strcmp(args[2], "-r") == 0) {
            ls_response = get_ls(user, args[1], true, false);
        } else if(strcpy(args[2],"-f") == 0) {
            files_only = true;
            ls_response = get_ls(user, args[1], false, true);
        } else {
            files_only = true;
            ls_response = get_ls(user, args[1], true, true);
        }
    }
    
    print_files(ls_response, files_only);
    free(ls_response);

    return 1;
}

int dbsh_cd(char** args) {
    if (args[1] == NULL) {
        fprintf(stderr, " expected argument to \"cd\"\n");
    } else if(args[2] == NULL) {
        if (chdir(args[1]) != 0) {
            perror("dbsh");
        }
    }
    return 1;
}

int dbsh_help(char** args) {
    int i;
    printf("---------------------------------------------------\n");
    printf("          Welcome to dbsh - DropBox Shell\n");
    printf("---------------------------------------------------\n");

    printf("Type program names and arguments, and hit enter.\n");
    printf("\n");
    printf("Available commands:\n");

    for (i = 0; i < dbsh_num_builtins(); i++) {
        printf("    %s\n", builtin_str_help[i]);
    }

    return 1;
}

int dbsh_exit(char **args) { return 0; }

int dbsh_launch(char **args) {
    pid_t pid, wpid;
    int status;

    pid = fork();
    if (pid == 0) {
        if (execvp(args[0], args) == -1) {
            perror("dbsh");
        }
        exit(EXIT_FAILURE);
    } else if (pid < 0) {
        perror("dbsh");
    } else {
        do {
            wpid = waitpid(pid, &status, WUNTRACED);
        } while (!WIFEXITED(status) && !WIFSIGNALED(status));
    }

    return 1;
}

int dbsh_execute(char **args) {
    int i;

    if (args[0] == NULL) {
        return 1;
    }

    for (i = 0; i < dbsh_num_builtins(); i++) {
        if (strcmp(args[0], builtin_str[i]) == 0) {
            return (*builtin_func[i])(args);
        }
    }

    return dbsh_launch(args);
}

/* OUTDATED
// char **dbsh_split_line(char *line) {
//     int bufsize = DBSH_TOK_BUFSIZE, position = 0;
//     char **tokens = malloc(bufsize * sizeof(char*));
//     char *token;

//     if (!tokens) {
//         fprintf(stderr, " allocation error\n");
//         exit(EXIT_FAILURE);
//     }

//     token = strtok(line, DBSH_TOK_DELIM);
//     while (token != NULL) {
//     tokens[position] = token;
//     position++;

//     if (position >= bufsize) {
//         bufsize += DBSH_TOK_BUFSIZE;
//         tokens = realloc(tokens, bufsize * sizeof(char*));
//         if (!tokens) {
//         fprintf(stderr, " allocation error\n");
//         exit(EXIT_FAILURE);
//         }
//     }

//     token = strtok(NULL, DBSH_TOK_DELIM);
//     }
//     tokens[position] = NULL;
//     return tokens;
// }*/

char **dbsh_split_line(char *line) {
    int bufsize = DBSH_TOK_BUFSIZE, position = 0;
    char **tokens = malloc(bufsize * sizeof(char*));
    char *token;
    int in_quotes = 0;
    char *start = line;

    if (!tokens) {
        fprintf(stderr, " allocation error\n");
        exit(EXIT_FAILURE);
    }

    // ls "Excel Python"
    while (*line) {
        if (*line == '"') {
            in_quotes = !in_quotes;
            if (!in_quotes) {
                *line = '\0';
                tokens[position++] = start;
                start = line + 1;
            } else {
                start = line + 1;
            }
        }
        else if (strchr(DBSH_TOK_DELIM, *line) && !in_quotes) {
            *line = '\0';
            if (start != line) {
                tokens[position++] = start;
            }
            start = line + 1;
        }
        line++;
        
        if (position >= bufsize) {
            bufsize += DBSH_TOK_BUFSIZE;
            tokens = realloc(tokens, bufsize * sizeof(char*));
            if (!tokens) {
                fprintf(stderr, " allocation error\n");
                exit(EXIT_FAILURE);
            }
        }
    }

    if (start != line) {
        tokens[position++] = start;
    }
    tokens[position] = NULL;
    return tokens;
}

char *dbsh_read_line(void) {
    int bufsize = DBSH_RL_BUFSIZE;
    int position = 0;
    char *buffer = malloc(sizeof(char) * bufsize);
    int c;

    if (!buffer) {
        fprintf(stderr, " allocation error\n");
        exit(EXIT_FAILURE);
    }

    while (1) {
        c = getchar();

        if (c == EOF || c == '\n') {
            buffer[position] = '\0';
            return buffer;
        } else {
            buffer[position] = c;
        }
        position++;

        if (position >= bufsize) {
            bufsize += DBSH_RL_BUFSIZE;
            buffer = realloc(buffer, bufsize);
            if (!buffer) {
            fprintf(stderr, " allocation error\n");
            exit(EXIT_FAILURE);
            }
        }
    }
}

void dbsh_loop(void) {
    char *line;
    char **args;
    int status;

    getchar();

    do {
        printf("\033[1;32mdbsh >\033[0m ");
        line = dbsh_read_line();
        args = dbsh_split_line(line);
        status = dbsh_execute(args);

        free(line);
        free(args);
    } while (status);
}

char* dbsh_trim_whitespace(char* str) {
    char *end;

    while (isspace((unsigned char)*str) || *str == '\n' || *str == '\r') str++;

    if (*str == 0)
        return str;

    end = str + strlen(str) - 1;
    while (end > str && (isspace((unsigned char)*end) || *end == '\n' || *end == '\r')) end--;

    *(end + 1) = 0;

    return str;
}

void dbsh_load_env(char* api_key, char* api_secret) {
    FILE* fp = fopen(".env", "r");
    if(!fp) {
        perror(" Unable to open .env file.\n");
        exit(EXIT_FAILURE);
    }

    char line[MAX_LINE_LENGTH];
    while(fgets(line, sizeof(line), fp)) {
        char* key = strtok(line, "=");
        char* value = strtok(NULL, "=");

        if(key && value) {
            key = dbsh_trim_whitespace(key);
            value = dbsh_trim_whitespace(value);

            if(strcmp("API_KEY", key) == 0){
                strncpy(api_key, value, MAX_LINE_LENGTH);
            } else if(strcmp("API_SECRET", key) == 0) {
                strncpy(api_secret, value, MAX_LINE_LENGTH);
            }
        }
    }
}

char* get_auth_code(char* api_key){
    char url[MAX_URL_LENGTH];
    char* authorize_code = (char*)malloc(sizeof(char) * MAX_AUTH_LENGTH);

    snprintf(url, sizeof(url), "https://www.dropbox.com/oauth2/authorize?client_id=%s&response_type=code", api_key);

    printf("Access \033[1;35m%s\033[0m and paste the code down below.\n", url);

    printf("Enter the generated code here: ");
    scanf("%s", authorize_code);

    if(authorize_code == NULL) {
        perror(" Error retrieving access code.\n");
        exit(EXIT_FAILURE);
    }

    return authorize_code;
}

char* get_oauth_token_json(char* auth_code, char* api_key, char* api_secret) {
    CURL *curl;
    CURLcode res;

    char post_data[BUFFER_SIZE];
    snprintf(post_data, sizeof(post_data),
            "code=%s&grant_type=authorization_code&client_id=%s&client_secret=%s",
            auth_code, api_key, api_secret);
            
    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();

    char* response_data = (char*)malloc(sizeof(char) * BUFFER_SIZE);

    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "https://api.dropbox.com/oauth2/token");
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, response_data);

        res = curl_easy_perform(curl);

        if(res != CURLE_OK) {
            fprintf(stderr, "Request failed: %s\n", curl_easy_strerror(res));
            perror(" Curl request could not be performed.\n");
        } 

        curl_easy_cleanup(curl);
    }

    curl_global_cleanup();

    return response_data;
}

char* get_account_json(struct user_data user) {
    CURL *curl;
    CURLcode res;

    char *response_data = (char*)malloc(BUFFER_SIZE * sizeof(char));
    if (response_data == NULL) {
        perror(" Error while creating pointer.\n");
        return NULL;
    }  
    response_data[0] = 0;

    cJSON *json_payload = cJSON_CreateObject();
    cJSON_AddStringToObject(json_payload, "account_id", user.account_id);
    char *json_string = cJSON_PrintUnformatted(json_payload);

    curl = curl_easy_init();
    if (curl) {
        struct curl_slist *headers = NULL;
        
        char auth_header[BUFFER_SIZE + 24];
        snprintf(auth_header, sizeof(auth_header) + 24, "Authorization: Bearer %s", user.auth_token);

        headers = curl_slist_append(headers, auth_header);
        headers = curl_slist_append(headers, "Content-Type: application/json");

        curl_easy_setopt(curl, CURLOPT_URL, "https://api.dropboxapi.com/2/users/get_account");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_string);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, response_data);

        res = curl_easy_perform(curl);

        if (res != CURLE_OK) {
            fprintf(stderr, " Request failed: %s\n", curl_easy_strerror(res));
            free(response_data);
            response_data = NULL;
        }

        curl_easy_cleanup(curl);
        curl_slist_free_all(headers);
    }

    free(json_string);
    cJSON_Delete(json_payload);

    return response_data;
}

void set_user_name(struct user_data* user) {
    char* res = get_account_json(*user);

    cJSON *json = cJSON_Parse(res);
    if (json == NULL) {
        perror(" Json could not open.\n");
        return;
    }

    cJSON *name_obj = cJSON_GetObjectItem(json, "name");
    if (name_obj != NULL) {
         cJSON *given_name_obj = cJSON_GetObjectItem(name_obj, "given_name");
        if (given_name_obj != NULL) {
            strncpy(
                user->username,
                given_name_obj->valuestring,
                MAX_AUTH_LENGTH
            );
        }
    } 

    cJSON_Delete(json);
}

void get_user_data(struct user_data *user, char* api_key, char* api_secret) {
    strncpy(user->auth_code, get_auth_code(api_key), MAX_AUTH_LENGTH); 
    
    char* json_response = get_oauth_token_json(
        user->auth_code,
        api_key,
        api_secret 
    );

    cJSON* json = cJSON_Parse(json_response);
    if(json != NULL) {
        cJSON* access_token_item = cJSON_GetObjectItem(json, "access_token");
        if (cJSON_IsString(access_token_item)) {
            strncpy(
                user->auth_token,
                access_token_item->valuestring,
                BUFFER_SIZE
            );
        }

        cJSON* token_type_item = cJSON_GetObjectItem(json, "token_type");
        if(cJSON_IsString(token_type_item)) {
            strncpy(
                user->token_type,
                token_type_item->valuestring,
                MAX_LINE_LENGTH
            );
        }

        cJSON* uid_item = cJSON_GetObjectItem(json, "uid");
        if(cJSON_IsString(uid_item)) {
            strncpy(
                user->user_id,
                uid_item->valuestring,
                MAX_AUTH_LENGTH
            );
        }

        cJSON* account_item = cJSON_GetObjectItem(json, "account_id");
        if(cJSON_IsString(account_item)) {
            strncpy(
                user->account_id,
                account_item->valuestring,
                MAX_AUTH_LENGTH
            );
        }
    } else {
        perror(" Json parser could not start properly.");
        exit(EXIT_FAILURE);
    }
}

bool is_authenticated(struct user_data user) {
    if (user.auth_code[0] == 0 
        || user.auth_token[0] == 0 
        || user.token_type[0] == 0
        || user.account_id[0] == 0 
        || user.user_id[0] == 0
        || user.username[0] == 0
    ) return false;

    return true;
}

void print(struct user_data user) {
    printf("accunt_id: %s\nauth_code: %s\nusername: %s\nuser_id: %s\n",user.account_id, user.auth_code, user.username, user.user_id);
}

void cls() {
    char** clear = malloc(sizeof(char**) * 2);
    clear[0] = "clear";
    clear[1] = NULL;
    dbsh_execute(clear);
    free(clear);
}

char* get_move_json(struct user_data user, char* from_path, char* to_path) {
    CURL *curl;
    CURLcode res;
    struct curl_slist *headers = NULL;
    char *response_data = (char *)malloc(BUFFER_SIZE * sizeof(char));

    if (response_data == NULL) {
        perror("Failed to allocate memory for response data");
        exit(EXIT_FAILURE);
    }
    response_data[0] = '\0';

    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();

    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "https://api.dropboxapi.com/2/files/move_v2");

        cJSON *root = cJSON_CreateObject();
        cJSON_AddBoolToObject(root, "allow_ownership_transfer", false);
        cJSON_AddBoolToObject(root, "allow_shared_folder", false);
        cJSON_AddBoolToObject(root, "autorename", false);
        cJSON_AddStringToObject(root, "from_path", from_path);
        cJSON_AddStringToObject(root, "to_path", to_path);

        char* json_data = cJSON_PrintUnformatted(root);

        char auth_header[BUFFER_SIZE];
        snprintf(auth_header, sizeof(auth_header) + 24, "Authorization: Bearer %s", user.auth_token);
        headers = curl_slist_append(headers, auth_header);
        headers = curl_slist_append(headers, "Content-Type: application/json");

        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_data);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, response_data);

        res = curl_easy_perform(curl);

        if (res != CURLE_OK) {
            fprintf(stderr, "CURL failed: %s\n", curl_easy_strerror(res));
        }

        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        cJSON_Delete(root);
    }

    curl_global_cleanup();

    return response_data;
}

void move_file(struct user_data user, char* src, char* dest) {
    char* json_res = get_move_json(user, src, dest);

    cJSON *root = cJSON_Parse(json_res);
    if (root == NULL) {
        fprintf(stderr, "Error parsing the response JSON\n");
        return;
    }

    cJSON *error = cJSON_GetObjectItem(root, "error");
    if (error != NULL) {
        cJSON *error_tag = cJSON_GetObjectItem(error, ".tag");
        if (error_tag != NULL) {
            printf("Error: %s\n", error_tag->valuestring);
        } else {
            printf("Unknown error in response\n");
        }
    }

    cJSON *error_summary = cJSON_GetObjectItem(root, "error_summary");
    if (error_summary != NULL) {
        printf("Error Summary: %s\n", error_summary->valuestring);
    }

    cJSON_Delete(root);
    return;
}

int dbsh_mv(char** args) {
    if(args[1] == NULL) {
        perror("Usage: mv <src> <dest>\n");
        return 1;
    } else if(args[2] == NULL) {
        perror("Usage: mv <src> <dest>\n");
        return 1;
    } else if(args[3] == NULL) {
        move_file(user, args[1], args[2]);
    }
    return 1;
}

char* get_copy_json(struct user_data user, char* from_path, char* to_path) {
    CURL *curl;
    CURLcode res;
    struct curl_slist *headers = NULL;
    char *response_data = (char *)malloc(BUFFER_SIZE * sizeof(char));

    if (response_data == NULL) {
        perror("Failed to allocate memory for response data");
        exit(EXIT_FAILURE);
    }
    response_data[0] = '\0';

    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();

    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "https://api.dropboxapi.com/2/files/copy_v2");

        cJSON *root = cJSON_CreateObject();
        cJSON_AddBoolToObject(root, "allow_ownership_transfer", false);
        cJSON_AddBoolToObject(root, "allow_shared_folder", false);
        cJSON_AddBoolToObject(root, "autorename", false);
        cJSON_AddStringToObject(root, "from_path", from_path);
        cJSON_AddStringToObject(root, "to_path", to_path);

        char* json_data = cJSON_PrintUnformatted(root);

        char auth_header[BUFFER_SIZE];
        snprintf(auth_header, sizeof(auth_header) + 24, "Authorization: Bearer %s", user.auth_token);
        headers = curl_slist_append(headers, auth_header);
        headers = curl_slist_append(headers, "Content-Type: application/json");

        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_data);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, response_data);

        res = curl_easy_perform(curl);

        if (res != CURLE_OK) {
            fprintf(stderr, "CURL failed: %s\n", curl_easy_strerror(res));
        }

        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        cJSON_Delete(root);
    }

    curl_global_cleanup();

    return response_data;
}

void copy_file(struct user_data user, char* src, char* dest) {
    char* json_res = get_copy_json(user, src, dest);

    cJSON *root = cJSON_Parse(json_res);
    if (root == NULL) {
        fprintf(stderr, "Error parsing the response JSON\n");
        return;
    }

    cJSON *error = cJSON_GetObjectItem(root, "error");
    if (error != NULL) {
        cJSON *error_tag = cJSON_GetObjectItem(error, ".tag");
        if (error_tag != NULL) {
            printf("Error: %s\n", error_tag->valuestring);
        } else {
            printf("Unknown error in response\n");
        }
    }

    cJSON *error_summary = cJSON_GetObjectItem(root, "error_summary");
    if (error_summary != NULL) {
        printf("Error Summary: %s\n", error_summary->valuestring);
    }

    cJSON_Delete(root);
    return;
}

int dbsh_cp(char** args) {
    if(args[1] == NULL) {
        perror("Usage: cp <src> <dest>\n");
        return 1;
    } else if(args[2] == NULL) {
        perror("Usage: cp <src> <dest>\n");
        return 1;
    } else if(args[3] == NULL) {
        copy_file(user, args[1], args[2]);
    }
    return 1;
}



char* get_mkdir_json(struct user_data user, char* PATH) {
    CURL *curl;
    CURLcode res;
    struct curl_slist *headers = NULL;
    char *response_data = (char *)malloc(BUFFER_SIZE * sizeof(char));

    if (response_data == NULL) {
        perror("Failed to allocate memory for response data");
        exit(EXIT_FAILURE);
    }
    response_data[0] = '\0';

    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();

    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "https://api.dropboxapi.com/2/files/create_folder_v2");

        cJSON *root = cJSON_CreateObject();
        cJSON_AddBoolToObject(root, "autorename", false);
        cJSON_AddStringToObject(root, "path", PATH);

        char* json_data = cJSON_PrintUnformatted(root);

        char auth_header[BUFFER_SIZE];
        snprintf(auth_header, sizeof(auth_header) + 24, "Authorization: Bearer %s", user.auth_token);
        headers = curl_slist_append(headers, auth_header);
        headers = curl_slist_append(headers, "Content-Type: application/json");

        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_data);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, response_data);

        res = curl_easy_perform(curl);

        if (res != CURLE_OK) {
            fprintf(stderr, "CURL failed: %s\n", curl_easy_strerror(res));
        }

        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        cJSON_Delete(root);
    }

    curl_global_cleanup();

    return response_data;
}

void mkdir(struct user_data user, char* PATH) {
    char* json_res = get_mkdir_json(user, PATH);
    bool errors = false;

    cJSON *root = cJSON_Parse(json_res);
    if (root == NULL) {
        fprintf(stderr, "Error parsing the response JSON\n");
        return;
    }

    cJSON *error = cJSON_GetObjectItem(root, "error");
    if (error != NULL) {
        errors = true;
        cJSON *error_tag = cJSON_GetObjectItem(error, ".tag");
        if (error_tag != NULL) {
            printf("Error: %s\n", error_tag->valuestring);
        } else {
            printf("Unknown error in response\n");
        }
    }

    cJSON *error_summary = cJSON_GetObjectItem(root, "error_summary");
    if (error_summary != NULL) {
        printf("Error Summary: %s\n", error_summary->valuestring);
    }

    cJSON_Delete(root);

    if(!errors)
        printf(GREEN_BOLD "Successfully created folder %s\n", PATH);

    return;
}

int dbsh_mkdir(char** args) {
    if(args[1] == NULL) {
        perror("Usage: mkdir <path>\n");
        return 1;
    } else if(args[2] == NULL) {
        mkdir(user, args[1]);
    }

    return 1;
}

char* get_delete_json(struct user_data user, char* PATH) {
    CURL *curl;
    CURLcode res;
    struct curl_slist *headers = NULL;
    char *response_data = (char *)malloc(BUFFER_SIZE * sizeof(char));

    if (response_data == NULL) {
        perror("Failed to allocate memory for response data");
        exit(EXIT_FAILURE);
    }
    response_data[0] = '\0';

    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();

    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "https://api.dropboxapi.com/2/files/delete_v2");

        cJSON *root = cJSON_CreateObject();
        cJSON_AddStringToObject(root, "path", PATH);
        char* json_data = cJSON_PrintUnformatted(root);

        char auth_header[BUFFER_SIZE];
        snprintf(auth_header, sizeof(auth_header) + 24, "Authorization: Bearer %s", user.auth_token);
        headers = curl_slist_append(headers, auth_header);
        headers = curl_slist_append(headers, "Content-Type: application/json");

        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_data);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, response_data);

        res = curl_easy_perform(curl);

        if (res != CURLE_OK) {
            fprintf(stderr, "CURL failed: %s\n", curl_easy_strerror(res));
        }

        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        cJSON_Delete(root);
    }

    curl_global_cleanup();

    return response_data;
}

void delete_path(struct user_data user, char* PATH) {
    printf("Are you sure you want to delete:\n    "RED"%s"RESET"\n(y / n)\n", PATH);
    char option;

    option = getchar();
    if(option == 'y' || option == 'Y') {
        char* json_res = get_delete_json(user, PATH);
        bool errors = false;

        cJSON *root = cJSON_Parse(json_res);
        if (root == NULL) {
            fprintf(stderr, "Error parsing the response JSON\n");
            return;
        }

        cJSON *error = cJSON_GetObjectItem(root, "error");
        if (error != NULL) {
            errors = true;
            cJSON *error_tag = cJSON_GetObjectItem(error, ".tag");
            if (error_tag != NULL) {
                printf("Error: %s\n", error_tag->valuestring);
            } else {
                printf("Unknown error in response\n");
            }
        }

        cJSON *error_summary = cJSON_GetObjectItem(root, "error_summary");
        if (error_summary != NULL) {
            printf("Error Summary: %s\n", error_summary->valuestring);
        }

        cJSON_Delete(root);

        if(!errors)
            printf(GREEN_BOLD "Successfully deleted path %s\n", PATH);

        return;
    }

    return;
}

int dbsh_rm(char** args) {
    if(args[1] == NULL) {
        perror("Usage: delete <path>\n");
        return 1;
    } else if(args[2] == NULL) {
        delete_path(user, args[1]);
    }

    return 1;
}

char* get_upload_json(struct user_data user, char* SAVE_PATH, char* file_path) {
    CURL *curl;
    CURLcode res;

    FILE* fp;
    char *file_data = NULL;
    long file_size = 0;

    fp = fopen(file_path, "rb");
    if (!fp) {
        perror("Unable to open file for uploading.\n");
        return NULL;
    }

    fseek(fp, 0, SEEK_END);
    file_size = ftell(fp);
    rewind(fp);

    file_data = (char *)malloc(file_size);
    if (!file_data) {
        perror("Memory allocation failed.\n");
        fclose(fp);
        return NULL;
    }
    fread(file_data, 1, file_size, fp);
    fclose(fp);

    struct curl_slist *headers = NULL;
    char *response_data = (char *)malloc(BUFFER_SIZE * sizeof(char));

    if (response_data == NULL) {
        perror("Failed to allocate memory for response data");
        exit(EXIT_FAILURE);
    }
    response_data[0] = '\0';

    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();

    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "https://content.dropboxapi.com/2/files/upload");

        curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, file_data);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, file_size);
        //curl_easy_setopt(curl, CURLOPT_INFILESIZE_LARGE, (curl_off_t)_filelength(_fileno(fp)));

        cJSON *root = cJSON_CreateObject();
        cJSON_AddBoolToObject(root, "autorename", false);
        cJSON_AddStringToObject(root, "mode", "add");
        cJSON_AddBoolToObject(root, "mute", false);
        cJSON_AddStringToObject(root, "path", SAVE_PATH);
        cJSON_AddBoolToObject(root, "strict_conflict", false);

        char* json_data = cJSON_PrintUnformatted(root);

        char auth_header[BUFFER_SIZE];
        char dropbox_api_header[BUFFER_SIZE];
        snprintf(auth_header, sizeof(auth_header) + 24, "Authorization: Bearer %s", user.auth_token);
        snprintf(dropbox_api_header, sizeof(dropbox_api_header), "Dropbox-API-Arg: %s", json_data);
        
        headers = curl_slist_append(headers, auth_header);
        headers = curl_slist_append(headers, dropbox_api_header);
        headers = curl_slist_append(headers, "Content-Type: application/octet-stream");

        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, response_data);

        res = curl_easy_perform(curl);

        printf("%s\n", json_data);

        if (res != CURLE_OK) {
            fprintf(stderr, "CURL failed: %s\n", curl_easy_strerror(res));
        }

        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        cJSON_Delete(root);
    }

    curl_global_cleanup();

    return response_data;
}

void upload_file(struct user_data user, char* SAVE_PATH, char* local_path) {
    printf("Uploading "GREEN_BOLD"%s"RESET" to "GREEN_BOLD"%s."RESET"\n" , local_path, SAVE_PATH);
    
    char* json_res = get_upload_json(user, SAVE_PATH, local_path);
    bool errors = false;

    cJSON *root = cJSON_Parse(json_res);
    if (root == NULL) {
        fprintf(stderr, "Error parsing the response JSON\n");
        return;
    }

    cJSON *error = cJSON_GetObjectItem(root, "error");
    if (error != NULL) {
        errors = true;
        cJSON *error_tag = cJSON_GetObjectItem(error, ".tag");
        if (error_tag != NULL) {
            printf("Error: %s\n", error_tag->valuestring);
        } else {
            printf("Unknown error in response\n");
        }
    }

    cJSON *error_summary = cJSON_GetObjectItem(root, "error_summary");
    if (error_summary != NULL) {
        printf("Error Summary: %s\n", error_summary->valuestring);
    }

    cJSON_Delete(root);

    if(!errors)
        printf(GREEN_BOLD "Successfully uploaded "GREEN_BOLD"%s\n" RESET, local_path);

    return;
}

int dbsh_put(char** args) {
    if(args[1] == NULL) {
        perror("Usage: put <save_path> <upload_file>\n");
        return 1;
    } else if(args[2] == NULL) {
        perror("Usage: put <save_path> <upload_file>\n");
        return 1;
    } else if(args[3] == NULL) {
        upload_file(user, args[1], args[2]);
    }

    return 1;
}

int main(int argc, char **argv) {
    cls();

    // Initialisation
    //TO DO: PKCE RATHER THAN DIRECT STORAGE OF SECRET
    dbsh_load_env(api_key, api_secret);
    get_user_data(&user, api_key, api_secret);
    set_user_name(&user);

    if(!is_authenticated(user)) {
        printf(RED "Could not log in.\n" RESET);
        exit(EXIT_FAILURE);
    }

    printf(GREEN_BOLD "Successfully logged in as %s.\n" RESET, user.username);

    // Shell loop
    dbsh_loop();

    // Exiting the shell
    return EXIT_SUCCESS;
}
