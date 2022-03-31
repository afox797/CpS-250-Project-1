#ifndef PROJECT_1_HASH_H
#define PROJECT_1_HASH_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <bsd/string.h>

typedef struct Ht_item Ht_item;
struct Ht_item {
    char *key;
    char *value;
};

typedef struct Hash_table Hash_table;
struct Hash_table {
    Ht_item **items;
    int size;
    int count;
};

#define CAPACITY 100
typedef unsigned long long int ull;

ull hash_function(char *str);
Ht_item* create_item(char *key, char *value);
Hash_table* create_table(int size);
void free_item(Ht_item *item);
void free_table(Hash_table *table);
void ht_insert(Hash_table *table, char *key, char *value);
char* ht_search(Hash_table* table, char* key);



#endif //PROJECT_1_HASH_H
