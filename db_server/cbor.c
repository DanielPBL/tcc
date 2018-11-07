#include "cbor.h"
#include <stdio.h>

int main(int argc, char * argv[])
{
    FILE * f = fopen(argv[1], "wb");
    /* Preallocate the map structure */
    cbor_item_t * root = cbor_new_definite_map(2);
    /* Add the content */
    cbor_map_add(root, (struct cbor_pair) {
        .key = cbor_move(cbor_build_string("user")),
        .value = cbor_move(cbor_build_string("daniel"))
    });
    cbor_map_add(root, (struct cbor_pair) {
        .key = cbor_move(cbor_build_string("pass")),
        .value = cbor_move(cbor_build_string("daniel"))
    });
    /* Output: `length` bytes of data in the `buffer` */
    unsigned char * buffer;
    size_t buffer_size, length = cbor_serialize_alloc(root, &buffer, &buffer_size);

    fwrite(buffer, 1, length, f);
    free(buffer);

    fclose(f);
    cbor_decref(&root);
}