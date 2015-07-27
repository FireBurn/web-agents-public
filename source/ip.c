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

#include "platform.h"
#include "am.h"
#include "utility.h"

#define IP6_32BIT_COMPONENTS 4

#ifndef s6_addr32
#ifdef __sun
#define s6_addr32   _S6_un._S6_u32
#elif __APPLE__
#define s6_addr32   __u6_addr.__u6_addr32
#endif
#endif

#ifdef _WIN32

struct win_in6_addr {

    union {
        uint8_t u6_addr8[16];
        uint16_t u6_addr16[8];
        uint32_t u6_addr32[4];
    } in6_u;
#ifdef s6_addr
#undef s6_addr
#endif

#ifdef s6_addr16
#undef s6_addr16
#endif

#ifdef s6_addr32
#undef s6_addr32
#endif

#define s6_addr     in6_u.u6_addr8
#define s6_addr16   in6_u.u6_addr16
#define s6_addr32   in6_u.u6_addr32
};

#define in6_addr win_in6_addr
#endif

/*
 * IPV6 presentation parser
 *
 * @return AM_TRUE if the string can be parsed as an ip v6 presentation
 */
static am_bool_t ipv6_parse(const char * p, struct in6_addr * n) {
    return INETPTON(AF_INET6, p, n) == 1;
}

/*
 * IPV4 presentation parser
 *
 * @return AM_TRUE if the string can be parsed as an ip v4 presentation
 */
static am_bool_t ipv4_parse(const char * p, struct in_addr * n) {
    return INETPTON(AF_INET, p, n) == 1;
}

/*
 * IPV6 presentation parser for a subsection of a string specified by length
 *
 * @return AM_TRUE if the section of a string can be parsed as an ip v6 presentation
 */
static am_bool_t ipv6_parse_section(const char * p, size_t length, struct in6_addr * n) {
    am_bool_t output;
    char * a = strndup(p, length);
    if (a) {
        output = ipv6_parse(a, n);
        free(a);
    } else {
        output = AM_FALSE;
    }
    return output;
}

/*
 * IPV4 presentation parser for a subsection of a string specified by length
 *
 * @return AM_TRUE if the section of a string can be parsed as an ip v4 presentation
 */
static am_bool_t ipv4_parse_section(const char * p, size_t length, struct in_addr * n) {
    am_bool_t output;
    char * a = strndup(p, length);
    if (a) {
        output = ipv4_parse(a, n);
        free(a);
    } else {
        output = AM_FALSE;
    }
    return output;
}

/*
 * Modify the binary address to set only the network mask bits
 */
static void ipv6_set_mask(struct in6_addr * n, int bits) {
    int quads = bits >> 5;                      /* number of whole quads masked = bits/32 */
    int remainder = bits & 0x1F;                /* number of bits masked in the subsequent quad = bits%32 */

    if (quads < 4 && remainder)
        n->s6_addr32 [quads++] &= htonl(0xFFFFFFFFu << (32 - remainder));

    while (quads < 4)
        n->s6_addr32 [quads++] = 0;
}

/*
 * Modify the binary address to set only the network mask bits
 */
static void ipv4_set_mask(struct in_addr * n, int bits) {
    n->s_addr &= htonl(0xFFFFFFFFu << (32 - bits));
}

/*
 * Convert ip v6 presentation to binary and set network mask if CIDR notation is present
 *
 * @return number of bits in the network mask, 128 if no CIDR mask is present
 */
int ipv6_pton(const char * p, struct in6_addr * n) {
    char * e = strchr(p, '/');
    if (e) {
        char * endp;
        uint64_t bits64 = strtoul(e + 1, &endp, 10);

        if (e + 1 == endp)
            return -1;                          /* digits not present */

        if (* endp)
            return -1;                          /* junk after digits */

        if (128 < bits64)
            return -1;                          /* out of range */

        if (ipv6_parse_section(p, e - p, n)) {
            ipv6_set_mask(n, (int)bits64);
            return (int)bits64;
        }
    } else {
        if (ipv6_parse(p, n)) {
            return 128;                         /* no CIDR notation */
        }
    }
    return -1;                                  /* ip v6 part fails */
}

/*
 * Convert ip v4 presentation to binary and set network mask if CIDR notation is present
 *
 * @return number of bits in the network mask, 32 if no CIDR mask is present
 */
int ipv4_pton(const char * p, struct in_addr * n) {
    char * e = strchr(p, '/');
    if (e) {
        char * endp;
        uint64_t bits64 = strtoul(e + 1, &endp, 10);

        if (e + 1 == endp)
            return -1;                          /* digits not present */

        if (* endp)
            return -1;                          /* junk after digits */

        if (32 < bits64)
            return -1;                          /* out of range */

        if (ipv4_parse_section(p, e - p, n)) {
            ipv4_set_mask(n, (int) bits64);
            return (int) bits64;
        }
    } else {
        if (ipv4_parse(p, n)) {
            return 32;                         /* no CIDR notation */
        }
    }
    return -1;                                  /* ip v4 part fails */
}

/**
 * Test equivalence masked bits in two ipv4 addresses in network form
 * 
 * @return AM_TRUE if addr is within the masked ip v4 address range in net
 */
static am_bool_t cidr_match(const struct in_addr * addr, const struct in_addr * net, int bits) {
    if (bits == 0) {
        /* the range is all inclusive - uint32_t << 32 is undefined */
        return AM_TRUE;
    }

    /* here and in the function below, we are comparing quads (uint32_t) represented in the network byte
     * order. xor (^) is used to identify differences between the quads, and then << is used to remove the
     * differences outside of the network masks number of bits.
     */

    if ((addr->s_addr ^ net->s_addr) & htonl(0xFFFFFFFFu << (32 - bits)))
        return AM_FALSE;

    return AM_TRUE;
}

/**
 * Test masked bits in two ipv6 addresses in network form
 * 
 * @return AM_TRUE if addr is within the masked ip v6 address range in net
 */
static am_bool_t cidr6_match(const struct in6_addr * addr, const struct in6_addr * net, int bits) {
    const uint32_t * a = addr->s6_addr32;
    const uint32_t * n = net->s6_addr32;

    int quads = bits >> 5; /* number of whole quads masked = bits/32 */
    int remainder = bits & 0x1F; /* number of bits masked in the subsequent quad = bits%32 */

    if (quads) {
        if (memcmp(a, n, quads * sizeof (uint32_t))) {
            return AM_FALSE;
        }
    }

    if (remainder) {
        if ((a [quads] ^ n [quads]) & htonl(0xFFFFFFFFu << (32 - remainder))) {
            return AM_FALSE;
        }
    }
    return AM_TRUE;
}

/**
 * Tests whether the first argument is in the (inclusive) range of v6 addresses from adr_lo to addr_hi
 * 
 * @return 0 if the address is in the range
 */
static signed int cmp_ip_range(const struct in_addr * addr, const struct in_addr * addr_lo,
        const struct in_addr * addr_hi) {
    const uint32_t a = addr->s_addr;
    const uint32_t lo = addr_lo->s_addr;
    const uint32_t hi = addr_hi->s_addr;
    return ntohl(a) < ntohl(lo) ? -1 : ntohl(hi) < ntohl(a) ? 1 : 0;
}

/**
 *  Compares two uint32 arrays in network format (requiring ntohl translation)
 * 
 *  @return negative if a < b, positive if a > b, 0 if they are equal
 */
static signed int cmp_net(const uint32_t * a, const uint32_t * b) {
    int i, c = 0;
    for (i = IP6_32BIT_COMPONENTS; 0 < i--;) {
        uint32_t ha = ntohl(a [i]), hb = ntohl(b [i]);
        c = CMP(ha, hb);
        if (c) {
            break;
        }
    }
    return c;
}

/**
 * Tests whether the first argument is in the (inclusive) range of v6 addresses from adr_lo to addr_hi
 * 
 * @return 0 if the address is in the range, negative if below the range, positive if its above
 */
static signed int cmp_ip6_range(const struct in6_addr * addr, const struct in6_addr * addr_lo, const struct in6_addr * addr_hi) {
    int c;
    c = cmp_net(addr_lo->s6_addr32, addr->s6_addr32);
    if (0 < c) {
        return -1;
    }
    c = cmp_net(addr->s6_addr32, addr_hi->s6_addr32);
    if (0 < c) {
        return 1;
    }
    return 0;
}

/**
 * Initialize and read an ipv4 presentation, returning in bpits the number of bits
 * 
 * @return AM_FALSE if the presentation cannot be read as an ipv4 address in CIDR notation
 */
static am_bool_t read_ip(const char * p, struct in_addr * n, int * pbits) {
    *pbits = ipv4_pton(p, n);
    if (*pbits == -1) {
        return AM_FALSE;
    }
    return AM_TRUE;
}

/**
 * Read an ipv4 presentation p, expecting all bits to be masked, i.e. not a range
 * 
 * @return AM_FALSE if the presentation is not ipv4, or if it is a CIDR range
 */
static am_bool_t read_full_ip(const char * p, struct in_addr * n) {
    int mask;
    if (read_ip(p, n, &mask)) {
        if (mask == sizeof (n->s_addr) * 8) {
            return AM_TRUE;
        }
    }
    return AM_FALSE;
}

/**
 * Initialize and read the ipv6 presentation, returning in pbits the number of masked (on) bits
 * 
 * @return AM_FALSE iff the presentation form cannot be parsed as an ipv6 address in CIDR notation
 */
static am_bool_t read_ip6(const char * p, struct in6_addr * n, int * pbits) {
    *pbits = ipv6_pton(p, n);
    if (*pbits == -1) {
        return AM_FALSE;
    }
    return AM_TRUE;
}

/**
 * Read the presentation form of an ipv6 address, expecting all bits to be masked (on)
 * 
 * @return AM_TRUE if all bits are masked (on).
 */
static am_bool_t read_full_ip6(const char * ip, struct in6_addr * p) {
    int mask;
    if (read_ip6(ip, p, &mask)) {
        if (mask == sizeof (p->s6_addr32) * 8) {
            return AM_TRUE;
        }
    }
    return AM_FALSE;
}

/**
 * Test whether an ip address falls within two inclusive boundaries, ensuring that
 * all addresses are of the same family, v4 or v6, and are not ranges.
 *
 * @return AM_TRUE for success, false on address parse error or out of bounds
 */
static am_bool_t test_within_bounds(const char * addr_p, const char * lo_p, const char * hi_p) {
    struct in_addr addr;
    struct in6_addr addr6;
    if (read_full_ip(addr_p, &addr)) {
        struct in_addr lo, hi;
        if (read_full_ip(lo_p, &lo) && read_full_ip(hi_p, &hi)) {
            return cmp_ip_range(&addr, &lo, &hi) == 0;
        }
    } else if (read_full_ip6(addr_p, &addr6)) {
        struct in6_addr lo6, hi6;
        if (read_full_ip6(lo_p, &lo6) && read_full_ip6(hi_p, &hi6)) {
            return cmp_ip6_range(&addr6, &lo6, &hi6) == 0;
        }
    }
    return AM_FALSE;
}

/**
 * Parse a <LO>-<HI> ip address range, and test that an ip address is in that range
 * 
 * @return 0 on success
 */
static am_status_t get_in_bounded_range_status(const char * addr, const char * range) {
    int c;
    char *lo_p, *hi_p;
    char *p = strchr(range, '-');
    if (p == NULL) {
        return AM_ENOMEM;
    }
    lo_p = strndup(range, p - range);
    hi_p = strdup(p + 1);
    if (lo_p && hi_p) {
        c = test_within_bounds(addr, lo_p, hi_p) ? AM_SUCCESS : AM_NOT_FOUND;
    } else {
        c = AM_ENOMEM;
    }
    am_free(lo_p);
    am_free(hi_p);
    return c;
}

/**
 * Test that an ip address is within a range specified by a CIDR in the same address family (v4 or v6).
 *
 * @return AM_SUCCESS on match else NOT_FOUND
 */
static am_status_t get_in_masked_range_status(const char * addr, const char * range) {
    struct in_addr addr4;
    struct in6_addr addr6;
    int bits;
    if (read_full_ip(addr, &addr4)) {
        struct in_addr cidr;
        if (read_ip(range, &cidr, &bits)) {
            return cidr_match(&addr4, &cidr, bits) ? AM_SUCCESS : AM_NOT_FOUND;
        }
    } else if (read_full_ip6(addr, &addr6)) {
        struct in6_addr cidr;
        if (read_ip6(range, &cidr, &bits)) {
            return cidr6_match(&addr6, &cidr, bits) ? AM_SUCCESS : AM_NOT_FOUND;
        }
    }
    return AM_NOT_FOUND;
}

/**
 * Test that an ip address is within a range in the same address family (v4 or v6).
 *
 * @return AM_SUCCESS on match, else NOT_FOUND
 */
am_status_t ip_address_match(const char *ip, const char **list, unsigned int listsize, unsigned long instance_id) {
    unsigned int i;
    if (ip == NULL || list == NULL || listsize == 0) {
        return AM_EINVAL;
    }

    for (i = 0; i < listsize; i++) {
        const char *hp = strchr(list[i], '-');
        const char *fs = strchr(list[i], '/');

        if (hp != NULL && fs == NULL) {
            /* make sure we get address range here: 192.168.1.1-192.168.2.3 */
            if (get_in_bounded_range_status(ip, list[i]) == AM_SUCCESS) {
                AM_LOG_INFO(instance_id, "ip_address_match(): found ip address %s in address range %s", ip, list[i]);
                return AM_SUCCESS;
            }
        }

        if (hp == NULL && fs != NULL) {
            /* and cidr spec here: 192.168.1.1/24 */
            if (get_in_masked_range_status(ip, list[i]) == AM_SUCCESS) {
                AM_LOG_INFO(instance_id, "ip_address_match(): found ip address %s in address range %s", ip, list[i]);
                return AM_SUCCESS;
            }
        }
    }
    return AM_NOT_FOUND;
}
