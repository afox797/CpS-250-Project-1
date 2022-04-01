#include "hash.h"


ull hash_function(const char *str) {
    if (str == NULL) {
        return -1;
    }

    ull i = 0;
    for (int j = 0; str[j]; j++) {
        i += str[j];
    }
    return i % CAPACITY;
}

Ht_item* create_item(char *key, char *value) {
    Ht_item *item = malloc(sizeof(Ht_item));

    item->key = (char*)malloc((strlen(key) + 1));
    item->value = (char*)malloc((strlen(value) + 1));

    strlcpy(item->key, key, strlen(key) + 1);
    strlcpy(item->value, value, strlen(value) + 1);

    return item;
}

Hash_table* create_table(int size) {
    Hash_table *table = (Hash_table*) malloc(sizeof(Hash_table));
    table->size = size;
    table->count = 0;
    table->items = (Ht_item**) calloc(table->size, sizeof(Ht_item*));
    for (int i = 0; i < table->size; ++i) {
        table->items[i] = NULL;
    }

    return table;
}

void free_item(Ht_item *item) {
    free(item->key);
    free(item->value);
    free(item);
}

void free_table(Hash_table *table) {
    for (int i = 0; i < table->size; ++i) {
        Ht_item *item = table->items[i];
        if (table->items[i] != NULL) {
            free_item(item);
        }
    }
    free(table->items);
    free(table);
}

void ht_insert(Hash_table *table, char *key, char *value) {
    int index = hash_function(key);
    Ht_item *item = create_item(key, value);
    Ht_item *current = table->items[index];
    if (current == NULL) {
        if (table->count == table->size) {
            printf("Table is full\n");
            free_item(item);
            return;
        }
        table->items[index] = item;
        table->count++;
    } else {
        if (strcmp(current->key, key) == 0) {
            strlcpy(table->items[index]->value, value, strlen(value) + 1);
            return;
        } else {
            return;
        }
    }
}

char* ht_search(Hash_table* table, char* key) {
    int index = hash_function(key);

    if (index == -1) {
        return NULL;
    }

    Ht_item* item = table->items[index];

    if (item != NULL) {
        if (strcmp(item->key, key) == 0) {
            return item->value;
        }
    }
    return NULL;
}

