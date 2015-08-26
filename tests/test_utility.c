/**
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2015 ForgeRock AS.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <setjmp.h>

#include "am.h"
#include "platform.h"
#include "utility.h"
#include "log.h"
#include "cmocka.h"


/**
 * This is the marker we spatter throughout our destination buffer for testing purposes.  It must not be null
 * because as far as this code is concerned, null is valid data.  We need this to be invalid and noticable.
 * Thus I chose control A.
 */
#define MARKER   0x1


/**
 * Encode the string stored in p and make non printing characters (including nulls) visible by representing
 * them as \HH where HH is the hex value in the shortest width possible (so null comes out as \0).  We return
 * a pointer to a dynamically allocated piece of memory which should be freed.  This routine isn't particularly
 * efficient.
 */
static const char* encode(const char* p, size_t len) {
    static char buf[1024];
    
    buf[0] = '\0';
    while(len--) {
        char buf2[50];
        if (*p < ' ' || *p == 127) {
            sprintf(buf2, "\\%x", *p);
            strcat(buf, buf2);
        } else {
            buf2[0] = *p;
            buf2[1] = '\0';
            strcat(buf, buf2);
        }
        p++;
    }
    return strdup(buf);
}

/**
 * Find the first marker character in "dest" and return the number of characters before it.
 */
static size_t find_marker(const char* dest) {
    
    const char* p = dest;
    while (*p != MARKER) {
        p++;
    }
    return p - dest;
}

/**
 * Compare the actual and expected values.  If they do not match, dump out a representation of both the expected
 * and actual values so we can see what has gone wrong.  If they do match, print "SUCCESS" and return 0.  In
 * this way we draw maximum attention to ourselves only if the test fails.
 */
static int compare(const char* actual, const char* expected, size_t expected_len) {
    
    size_t actual_len = find_marker(actual);
    
    if (actual_len != expected_len) {
        printf("actual length and expected lengths are different (%lu vs %lu)\n",
               actual_len, expected_len);

        printf("expected: %s\nactual: %s\n", encode(expected, expected_len), encode(actual, actual_len));
        return 1;
    }

    if (memcmp(actual, expected, expected_len) != 0) {
        printf("actual and expected strings are different (although the same length)\n");
        printf("expected: %s\nactual: %s\n", encode(expected, expected_len), encode(actual, actual_len));
        return 1;
    }
    
    return 0;
}

/************************************************************************************************************/

static const char* richard3 = "Now is the winter of our discontent, "
                                "Made glorious summer by this son of York";

static const char* as_you_like_it_1 = "All the world's a stage, and all the men and women merely players";
static const char* as_you_like_it_2 = "they have their exits and their entrances";
static const char* as_you_like_it_3 = "and one man in his time plays many parts, his acts being seven ages";

/************************************************************************************************************/

/**
 * test mem2cpy, returning 1 if the test fails, 0 if it succeeds.
 */
void test_mem2cpy(void** state) {

    (void)state;

    char a[] = "ABCDEF";
    char b[] = "GHI";

    char expected[] = "ABCDEF\0GHI"; // C gives us a free null after the "I"

    char dest[1000];
    
    memset(dest, MARKER, ARRAY_SIZE(dest));
    mem2cpy(dest, a, 6, b, 3);

    assert_int_equal(compare(dest, expected, ARRAY_SIZE(expected)), 0);
}

/**
 * test mem3cpy, returning 1 if the test fails, 0 if it succeeds.
 */
void test_mem3cpy(void** state) {

    (void)state;

    char a[] = "ABCDEF";
    char b[] = "GHI";
    char c[] = "JKLMN";

    char expected[] = "ABCDEF\0GHI\0JKLMN"; // C gives us a free null after the "N"

    char dest[1000];

    memset(dest, MARKER, ARRAY_SIZE(dest));
    mem3cpy(dest, a, 6, b, 3, c, 5);

    assert_int_equal(compare(dest, expected, ARRAY_SIZE(expected)), 0);
}

/**
 * Test the match function.
 */
void test_match(void** state) {
    
    (void)state;
    
    // for some reason, passing in null results in an "ok" match
    assert_int_equal(match(1, NULL, NULL), AM_OK);
    assert_int_equal(match(1, NULL, richard3), AM_OK);
    assert_int_equal(match(1, richard3, NULL), AM_OK);
    
    assert_int_equal(match(1, richard3, "content,"), AM_OK);
    assert_int_equal(match(1, richard3, "ter.of..ur"), AM_OK);
    assert_int_equal(match(1, richard3, "[Gg]lorio.s"), AM_OK);
    
    assert_int_equal(match(1, richard3, "Aardvark,"), AM_FAIL);
    assert_int_equal(match(1, richard3, "[Gg]lourio.s"), AM_FAIL);
}

/**
 * Note that the match_groups function isn't tested here because it is only invoked once in the entire codebase.
 * Also I can't quite figure what the length parameters should be set to.
 */



static int am_vasprintf_test(char** p, const char* format, ...) {

    int result;
    va_list args;

    va_start(args, format);
    result = am_vasprintf(p, format, args);
    va_end(args);

    return result;
}

/**
 * Test the am_vasprintf function.
 */
void test_am_vasprintf(void** state) {

    char  random[5];
    char* buff = random; /* ensure we won't crash if passed a pointer referencing the stack */

    int returned = am_vasprintf_test(&buff, "%s: %s; %s", as_you_like_it_1, as_you_like_it_2, as_you_like_it_3);

    assert_non_null(buff);
    
    int correct_length = strlen(as_you_like_it_1) + 2 + strlen(as_you_like_it_2) + 2 + strlen(as_you_like_it_3);
    
    assert_int_equal(returned, correct_length);
    assert_int_equal(strlen(buff), correct_length);
    
    free(buff);
}

/**
 * test the am_asprintf function.  Obviously one thing we cannot do is pass it a pointer to the
 * stack as it's first parmameter - if we do, it crashes.
 */
void test_am_asprintf(void** state) {

    char* buff = NULL;
    char  check[1024];
    
    am_asprintf(&buff, "%s: ", as_you_like_it_1);
    am_asprintf(&buff, "%s%s; ", buff, as_you_like_it_2);
    am_asprintf(&buff, "%s%s", buff, as_you_like_it_3);

    assert_non_null(buff);
    
    strcpy(check, as_you_like_it_1);
    strcat(check, ": ");
    strcat(check, as_you_like_it_2);
    strcat(check, "; ");
    strcat(check, as_you_like_it_3);
    
    assert_string_equal(buff, check);

    free(buff);
}

/**
 * test the am_free function.  Obviously we can't pass a stack-based reference to it, that will cause it
 * to crash.  Similarly we can only pass a pointer directly returned from one of the memory allocation functions,
 * as opposed to something returned and incremented a little.
 */
void test_am_free(void** state) {

    void* m_buff = malloc(8192);
    void* c_buff = calloc(2, 512);
    void* r_buff = malloc(256); r_buff = realloc(r_buff, 1024);
    
    am_free(NULL);
    am_free(m_buff);
    am_free(c_buff);
    am_free(r_buff);
    
    /* this is about the only thing I can think of asserting here
     * at least it "proves" we made it this far.
     */
    assert_true(1);
}

/**
 * test am_strldup, which duplicates a lowercase version of the string into dynamic memory.
 * In fact am_stridup was only written while tidying up stristr.
 */
void test_am_strldup(void** state) {
    
    char* should_be_null = am_strldup(NULL);
    char* lowercase_text1 = am_strldup(as_you_like_it_1);
    char* lowercase_text2 = am_strldup(as_you_like_it_2);

    assert_null(should_be_null);
    assert_string_equal(lowercase_text1, "all the world's a stage, and all the men and women merely players");
    assert_string_equal(lowercase_text2, as_you_like_it_2);
    
    am_free(should_be_null);
    am_free(lowercase_text1);
    am_free(lowercase_text2);
    
    /* this at least proves we survived the freeing */
    assert_true(1);
}

#define START   "NoW iS tHe Win"
#define MIDDLE  "TER"
#define END     " OF OuR diSCOnteNT"

/**
 * Test case insensitive string searching.
 */
void test_stristr(void** state) {
    
    char* text = START MIDDLE END;
    char* lower_text = am_strldup(text);
    char* lower_start = am_strldup(START);
    char* lower_middle = am_strldup(MIDDLE);

    char* pos1 = stristr(text, MIDDLE);
    char* pos2 = stristr(text, lower_middle);

    char* pos3 = stristr(lower_text, MIDDLE);
    char* pos4 = stristr(lower_text, lower_middle);
    
    char* pos5 = stristr(text, START);
    char* pos6 = stristr(text, lower_start);
    
    assert_non_null(pos1);
    assert_non_null(pos2);
    assert_ptr_equal(pos1, pos2);
    
    assert_non_null(pos3);
    assert_non_null(pos4);
    assert_ptr_equal(pos3, pos4);
    
    assert_int_equal(pos3 - lower_text, pos1 - text);
    
    assert_non_null(pos5);
    assert_non_null(pos6);
    assert_int_equal(pos5 - text, 0);
    assert_int_equal(pos6 - text, 0);
}

/**
 * Test base 64 encoding and decoding.  Note that https://www.base64encode.org/ has been
 * particularly helpful here.  Also note the importance of setting "length" correctly before
 * its address is passed into the encoding function.  The decoding function doesn't care.
 */
void test_base64_encode_decode(void** state) {
    
    const char* in = "Man";
    const char* out = "TWFu";
    const char* r3_out = "Tm93IGlzIHRoZSB3aW50ZXIgb2Ygb3VyIGRpc2NvbnRlbnQsIE1hZGUgZ2xvcmlvdXMgc3VtbWVyIGJ5IHRoaXMgc29uIG9mIFlvcms=";
    size_t length = 3;
    
    char* encoded = base64_encode(in, &length);
    assert_non_null(encoded);
    assert_string_equal(encoded, out);
    assert_int_equal(length, strlen(out));
    
    char* decoded = base64_decode(out, &length);
    assert_non_null(decoded);
    assert_string_equal(decoded, in);
    assert_int_equal(length, strlen(in));
    
    length = strlen(richard3);
    encoded = base64_encode(richard3, &length);
    decoded = base64_decode(encoded, &length);
    
    assert_string_equal(encoded, r3_out);
    assert_string_equal(richard3, decoded);
}

/**
 * Note that I can't think of a good way to test delete_am_cookie_list.
 */


/**
 * Test the rather odd char_count function,
 */
void test_char_count(void** state) {
    
    int last;
    int result = char_count(richard3, 'e', &last);
    
    assert_int_equal(result, 5);
    assert_int_equal(last, richard3[strlen(richard3) - 1]);
    
    result = char_count(as_you_like_it_1, 't', NULL);
    assert_int_equal(result, 3);
    
    result = char_count(as_you_like_it_3, '\t', &last);
    assert_int_equal(result, 0);
    assert_int_equal(last, as_you_like_it_3[strlen(as_you_like_it_3) - 1]);
}


/**
 * Test encryption and decryption.  This function does the obvious test of taking text, encoding
 * it and decoding it again to see if we end up with the same thing.
 */
void test_encrypt_decrypt_password(void** state) {
    const char* key = "jU7tHgf1iB4gbTR7";
    char* clear_text = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    
    char* result = strdup(clear_text);
    size_t length = strlen(key);
    
    char* encoded = base64_encode(key, &length);
    assert_non_null(encoded);
    encrypt_password(encoded, &result);

    // "result" now points to a dynamically allocated area filled with the encrypted password
    assert_string_not_equal(clear_text, result);

    // now decode back to the original text (hopefully)
    decrypt_password(encoded, &result);
    assert_string_equal(result, clear_text);
}

/**
 * Test the escaping of characters supported by xml_entity_escape.
 */
void test_xml_entity_escape(void** state) {
    
    char buff[1024] = "one&two'three\"four>five<six";
    
    char* amp;
    char* apos;
    char* quot;
    char* gt;
    char* lt;

    xml_entity_escape(buff, strlen(buff));
    
    amp = strstr(buff, "one&amp;two");
    apos = strstr(buff, "two&apos;three");
    quot = strstr(buff, "three&quot;four");
    gt = strstr(buff, "four&gt;five");
    lt = strstr(buff, "five&lt;six");
    
    assert_non_null(amp);
    assert_ptr_equal(amp, buff);
    assert_non_null(apos);
    assert_non_null(quot);
    assert_non_null(gt);
    assert_non_null(lt);
}

/**
 * Test the rather odd am_strsep function.
 */
void test_am_strsep(void** state) {
    
    char buff[1024] = "abc%def%ghi%jkl%mno%pqr%stu%vwx%yza";
    char* temp = buff;
    char* match;
    int counter = 0;
    
    /* Note: do not use a multi character separator */
    while((match = am_strsep(&temp, "%")) != NULL) {
        counter++;
        assert_int_equal(strlen(match), 3);
        assert_int_equal((match - buff) % 4, 0);
    }
    assert_int_equal(counter, 9);
}

#define PROTO1   "http"
#define HOST1    "the.site.com"
#define PORT1    "9010"
#define PATH1    "/path/to/resource"
#define QUERY1   "?key12=value12&key2=value2#anchor"

#define PROTO2   "https"
#define HOST2    "mostly-landscapes.net"
#define PATH2    "/short/path/foo.html"

#define PROTO3  "http"
#define HOST3   "_cryptic-world_.com"
#define PORT3   "1234"


/**
 * Test the parsing of URLs.
 */
void test_parse_url(void** state) {
    
    char buff1[] = PROTO1 "://" HOST1 ":" PORT1 PATH1 QUERY1;
    char buff2[] = PROTO2 "://" HOST2 PATH2;
    char buff3[] = PROTO3 "://" HOST3;
    char buff4[] = PROTO3 ":??" "BAD url";
    
    struct url url_struct;
    int result;
    
    result = parse_url(buff1, &url_struct);
    assert_int_equal(url_struct.port, atoi(PORT1));
    assert_int_equal(url_struct.error, 0);
    assert_int_equal(url_struct.ssl, 0);
    assert_string_equal(url_struct.proto, PROTO1);
    assert_string_equal(url_struct.host, HOST1);
    assert_string_equal(url_struct.path, PATH1);
    assert_string_equal(url_struct.query, QUERY1);
    assert_int_equal(result, AM_SUCCESS);
    
    result = parse_url(buff2, &url_struct);
    assert_int_equal(url_struct.port, 443);
    assert_int_equal(url_struct.error, 0);
    assert_int_equal(url_struct.ssl, 1);
    assert_string_equal(url_struct.proto, PROTO2);
    assert_string_equal(url_struct.host, HOST2);
    assert_string_equal(url_struct.path, PATH2);
    assert_string_equal(url_struct.query, "");
    assert_int_equal(result, AM_SUCCESS);

    result = parse_url(buff3, &url_struct);
    assert_int_equal(url_struct.port, 80);
    assert_int_equal(url_struct.error, 0);
    assert_int_equal(url_struct.ssl, 0);
    assert_string_equal(url_struct.proto, PROTO3);
    assert_string_equal(url_struct.host, HOST3);
    assert_string_equal(url_struct.path, "/");
    assert_string_equal(url_struct.query, "");
    assert_int_equal(result, AM_SUCCESS);

    result = parse_url(buff4, &url_struct);
    assert_int_not_equal(url_struct.error, 0);
    assert_int_equal(result, AM_ERROR);
}

/**
 * test the url encode and decode functions.
 */
void test_url_encode_decode(void** state) {
    char buff[] = "abc !\"#$'+(here)--[:>>>there<<<]*+/-?@{xxx}.";
    char test_a[] = "%20a";
    char test_b[] = "a%20";
    char test_c[] = "a% %1";
    char test_d[] = "% %20%x +%";
    char test_e[] = "%C4%81%C4%8D%C4%93%C4%A3%C4%AB%C4%B7%C4%BC%C5%86%C5%A1%C5%AB%C5%BE";
    
    char* encoded = url_encode(buff);
    char* decoded = url_decode(encoded);
    
    assert_non_null(encoded);
    assert_non_null(decoded);
    assert_string_equal(buff, decoded);
    free(encoded);
    free(decoded);
    
    buff[0] = '\0';
    encoded = url_encode(buff);
    decoded = url_decode(buff);
    
    assert_non_null(encoded);
    assert_non_null(decoded);
    assert_string_equal(decoded, "");
    free(encoded);
    free(decoded);
    
    decoded = url_decode(test_a);
    assert_non_null(decoded);
    assert_string_equal(decoded, " a");
    free(decoded);
    
    decoded = url_decode(test_b);
    assert_non_null(decoded);
    assert_string_equal(decoded, "a ");
    free(decoded);
    
    decoded = url_decode(test_c);
    assert_non_null(decoded);
    assert_string_equal(decoded, "a% %1");
    free(decoded);
    
    decoded = url_decode(test_d);
    assert_non_null(decoded);
    assert_string_equal(decoded, "%  %x  %");
    free(decoded);
    
    decoded = url_decode(test_e);
    assert_non_null(decoded);
    assert_string_equal(decoded, "āčēģīķļņšūž");
    free(decoded);
}

void test_url_encode_decode_agent3(void** state) {
    char agent3_input1[] = "~a!a@a#a$a%a^a&";
    char agent3_output1[] = "%7Ea%21a%40a%23a%24a%25a%5Ea%26";
    
    char agent3_input2[] = "!@#$%^&*()_+{}:\".,/\\";
    char agent3_output2[] = "%21%40%23%24%25%5E%26*%28%29_%2B%7B%7D%3A%22.%2C%2F%5C";

    char* agent4_decoded = url_decode(agent3_output1);
    assert_non_null(agent4_decoded);
    assert_string_equal(agent4_decoded, agent3_input1);
    free(agent4_decoded);

    agent4_decoded = url_decode(agent3_output2);
    assert_non_null(agent4_decoded);
    assert_string_equal(agent4_decoded, agent3_input2);
    free(agent4_decoded);
}

void test_string_replace(void ** state) {
    char * original;
    size_t size;

    original = strdup("abcXXXdefAM_AGENT_REALMXXXnXXXAM_AGENT_REALMv");
    size = strlen(original);
    assert_int_equal(string_replace(&original, "AM_AGENT_REALM", "realm1", &size), AM_SUCCESS);
    assert_string_equal("abcXXXdefrealm1XXXnXXXrealm1v", original);
    free(original);
    
    original = strdup("abcXXXdefAM_AGENT_REALMXXXnXXXAM_AGENT_REALM");
    size = strlen(original);
    assert_int_equal(string_replace(&original, "AM_AGENT_REALM", "realm1", &size), AM_SUCCESS);
    assert_string_equal("abcXXXdefrealm1XXXnXXXrealm1", original);
    free(original);
    
    original = strdup("abcXXXdefXXXnXXXv");
    size = strlen(original);
    assert_int_equal(string_replace(&original, "X", "YX", &size), AM_SUCCESS);
    assert_string_equal("abcYXYXYXdefYXYXYXnYXYXYXv", original);
    free(original);
    
    original = strdup("abcXXXdefXXXnXXX");
    size = strlen(original);
    assert_int_equal(string_replace(&original, "XXX", "YYY", &size), AM_SUCCESS);
    assert_string_equal(original, "abcYYYdefYYYnYYY");
    free(original);
 
    original = strdup("abcXXXdefXXXnXXX");
    size = strlen(original);
    assert_int_equal(string_replace(&original, "X", "YX", &size), AM_SUCCESS);
    assert_string_equal(original, "abcYXYXYXdefYXYXYXnYXYXYX");
    free(original);
    
    original = strdup("abcXXXdefXXXnXXX");
    size = strlen(original);
    assert_int_equal(string_replace(&original, "XXX", "Y", &size), AM_SUCCESS);
    assert_string_equal(original, "abcYdefYnY");
    free(original);
    
    original = strdup("abcXXXdefXXXnXXX");
    size = strlen(original);
    assert_int_equal(string_replace(&original, "X", "YYY", &size), AM_SUCCESS);
    assert_string_equal(original, "abcYYYYYYYYYdefYYYYYYYYYnYYYYYYYYY");
    free(original);
    
    original = strdup("abcXXXdefXXXnXXX");
    size = strlen(original);
    assert_int_equal(string_replace(&original, "XXX", "", &size), AM_SUCCESS);
    assert_string_equal(original, "abcdefn");
    free(original);
    
    original = strdup("abcXXXdefXXXnXXX");
    size = strlen(original);
    assert_int_equal(string_replace(&original, "", "YYY", &size), AM_NOT_FOUND);
    assert_string_equal(original, "abcXXXdefXXXnXXX");
    free(original);
    
}


