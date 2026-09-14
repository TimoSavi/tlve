/*
 *    tlve - a program to parse tag-length-value structures and print them in different formats
 *
 *    Copyright (C) 2009 Timo Savinen
 *    This file is part of tlve.
 *
 *    tlve is free software; you can redistribute it and/or modify
 *    it under the terms of the GNU General Public License as published by
 *    the Free Software Foundation; either version 2 of the License, or
 *    (at your option) any later version.
 *
 *    tlve is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU General Public License for more details.
 *
 *    You should have received a copy of the GNU General Public License
 *    along with tlve; if not, write to the Free Software
 *    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "tlve.h"

#ifdef HAVE_LIBFASTJSON_JSON_H
#include <libfastjson/json.h>
#ifndef json_object_to_file
#define json_object_to_file fjson_object_to_file
#endif
#ifndef json_object_from_file
#define json_object_from_file fjson_object_from_file
#endif
#elif defined(HAVE_JSON_C_JSON_H)
#include <json-c/json.h>
#elif defined(HAVE_JSON_JSON_H)
#include <json/json.h>
#elif defined(HAVE_JSON_H)
#include <json.h>
#endif

#ifdef HAVE_JSON

int json_mode = 0;
int json_pretty = 0;

struct json_level
{
    struct json_object *obj;
    struct json_object *children;
};

static struct json_level json_levels[MAX_LEVEL + 1];
static int json_current_depth = 0;

void
json_init(int pretty)
{
    json_mode = 1;
    json_pretty = pretty;
    json_current_depth = 0;
}

static void
json_emit_and_free(struct json_object *obj)
{
    const char *str;
#ifdef JSON_C_TO_STRING_PRETTY
    str = json_object_to_json_string_ext(obj, json_pretty ? JSON_C_TO_STRING_PRETTY : JSON_C_TO_STRING_PLAIN);
#else
    str = json_object_to_json_string(obj);
#endif
    if(str != NULL)
    {
        print_list_writes((char *)str);
        print_list_writec('\n');
    }
    json_object_put(obj);
}

void
json_add_primitive(struct tlvitem *item)
{
    struct json_object *obj;
    char *name;

    if(!json_mode || item == NULL) return;

    obj = json_object_new_object();
    name = print_list_get_item_name(item);

    json_object_object_add(obj, "name", json_object_new_string(name ? name : ""));
    json_object_object_add(obj, "tag", json_object_new_string(item->tag));
    json_object_object_add(obj, "type", json_object_new_string("primitive"));
    json_object_object_add(obj, "length", json_object_new_int64(item->length));
    json_object_object_add(obj, "offset", json_object_new_int64(item->file_offset));
    json_object_object_add(obj, "value", json_object_new_string(item->converted_value ? item->converted_value : ""));

    if(json_current_depth == 0)
    {
        json_emit_and_free(obj);
    }
    else
    {
        json_object_array_add(json_levels[json_current_depth].children, obj);
    }
}

void
json_add_constructed(struct tlvitem *item)
{
    struct json_object *obj;
    struct json_object *children;
    char *name;

    if(!json_mode || item == NULL) return;

    if(json_current_depth >= MAX_LEVEL)
    {
        panic("Maximum JSON nesting level reached", NULL, NULL);
    }

    obj = json_object_new_object();
    name = print_list_get_item_name(item);

    json_object_object_add(obj, "name", json_object_new_string(name ? name : ""));
    json_object_object_add(obj, "tag", json_object_new_string(item->tag));
    json_object_object_add(obj, "type", json_object_new_string("constructed"));
    json_object_object_add(obj, "form", json_object_new_string(item->form == T_INDEFINITE ? "indefinite" : "definite"));
    json_object_object_add(obj, "length", json_object_new_int64(item->length));
    json_object_object_add(obj, "offset", json_object_new_int64(item->file_offset));

    children = json_object_new_array();
    json_object_object_add(obj, "children", children);

    if(json_current_depth > 0)
    {
        json_object_array_add(json_levels[json_current_depth].children, obj);
    }

    json_current_depth++;
    json_levels[json_current_depth].obj = obj;
    json_levels[json_current_depth].children = children;
}

void
json_close_level(void)
{
    if(!json_mode || json_current_depth <= 0) return;

    if(json_current_depth == 1)
    {
        /* Top-level constructed item finished */
        struct json_object *root = json_levels[1].obj;
        json_levels[1].obj = NULL;
        json_levels[1].children = NULL;
        json_current_depth = 0;
        json_emit_and_free(root);
    }
    else
    {
        json_levels[json_current_depth].obj = NULL;
        json_levels[json_current_depth].children = NULL;
        json_current_depth--;
    }
}

void
json_finish(void)
{
    if(!json_mode) return;

    while(json_current_depth > 0)
    {
        json_close_level();
    }
}

#else

int json_mode = 0;
int json_pretty = 0;

void
json_init(int pretty)
{
    (void)pretty;
    panic("JSON output is not supported: libjson-c or libfastjson was not found at compile time", NULL, NULL);
}

void json_add_primitive(struct tlvitem *item) { (void)item; }
void json_add_constructed(struct tlvitem *item) { (void)item; }
void json_close_level(void) { }
void json_finish(void) { }

#endif
