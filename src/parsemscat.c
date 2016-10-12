/*
 * Copyright (c) 2016      Andreas Schneider <asn@samba.org>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <errno.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <libtasn1.h>
#include <gnutls/pkcs7.h>

#ifndef MIN
#define MIN(a,b) ((a)<(b)?(a):(b))
#endif

#define PKCS7_CTL_OBJID                "1.3.6.1.4.1.311.10.1"

#define CATALOG_LIST_OBJOID            "1.3.6.1.4.1.311.12.1.1"
#define CATALOG_LIST_MEMBER_OBJOID     "1.3.6.1.4.1.311.12.1.2"

#define CAT_NAME_VALUE_OBJID           "1.3.6.1.4.1.311.12.2.1"
#define CAT_MEMBERINFO_OBJID           "1.3.6.1.4.1.311.12.2.2"

struct mscat_context {
	gnutls_pkcs7_t pkcs7;
	gnutls_datum_t mscat_raw_data;
	ASN1_TYPE asn1_desc;
};

/*
gnutls_pkcs7_init()
gnutls_pkcs7_import(the der file)
gnutls_pkcs7_get_embedded_data_oid() - verify that this is the microsoft oid
gnutls_pkcs7_get_embedded_data(GNUTLS_PKCS7_EDATA_GET_RAW, &newderdata)
gnutls_pkcs7_deinit()
this will extract the part you are interested at
optionally at some point you may want to introduce verification of the data, but I skip it for now
*/

static void print_asc(const uint8_t *buf, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++) {
		printf("%c", isprint(buf[i]) ? buf[i] : '.');
	}
}

static void dump_data(const uint8_t *buf, size_t len)
{
	static const uint8_t empty[16] = { 0, };
	size_t i = 0;

	if (len <= 0) {
		return;
	}

	for (i = 0; i < len;) {
		if (i % 16 == 0) {
			if ((i > 0) &&
			    (len > i + 16) &&
			    (memcmp(&buf[i], &empty, 16) == 0)) {
				i += 16;
				continue;
			}

			if (i < len)  {
				printf("[%04zX] ", i);
			}
		}

		printf("%02x ", buf[i]);
		i++;

		if (i % 8 == 0) {
			printf("  ");
		}
		if (i % 16 == 0) {
			print_asc(&buf[i - 16], 8);
			printf(" ");
			print_asc(&buf[i - 8], 8);
			printf("\n");
		}
	}

	if (i % 16) {
		int n;
		n = 16 - (i % 16);
		printf(" ");
		if (n > 8) {
			printf(" ");
		}
		while (n--) {
			printf("   ");
		}
		n = MIN(8, i % 16);

		print_asc(&buf[i - (i % 16)], n);
		printf( " " );

		n = (i % 16) - n;
		if (n > 0) {
			print_asc(&buf[i - n], n);
		}
		printf("\n");
	}
}

static int mscat_read_file(const char *filename,
			   uint8_t **data,
			   unsigned int *data_len)
{
	struct stat sb = {0};
	size_t alloc_size;
	size_t req_size;
	size_t count;
	uint8_t *buf = NULL;
	FILE *fp;
	int rc;

	fp = fopen(filename, "r");
	if (fp == NULL) {
		return -1;
	}

	rc = fstat(fileno(fp), &sb);
	if (rc != 0) {
		goto error;
	}

	if (!S_ISREG(sb.st_mode)) {
		errno = EINVAL;
		goto error;
	}
	if (SIZE_MAX - 1 < (unsigned long)sb.st_size) {
		errno = ENOMEM;
		goto error;
	}
	alloc_size = sb.st_size + 1;

	buf = malloc(alloc_size);
	if (buf == NULL) {
		goto error;
	}

	req_size = alloc_size;

	count = fread(buf, 1, req_size, fp);
	if (count != req_size) {
		if (ferror(fp)) {
			goto error;
		}
	}
	buf[count] = '\0';
	fclose(fp);

	*data = buf;
	*data_len = count;

	return 0;
error:
	free(buf);
	fclose(fp);
	return rc;
}

static int mscat_import_pkcs7(struct mscat_context *mscat_ctx,
			      const char *filename)
{
	gnutls_datum_t mscat_data = {
		.size = 0,
	};
	const char *oid;
	int cmp;
	int rc;

	rc = gnutls_pkcs7_init(&mscat_ctx->pkcs7);
	if (rc != 0) {
		return -1;
	}

	rc = mscat_read_file(filename,
			     &mscat_data.data,
			     &mscat_data.size);
	if (rc == -1) {
		fprintf(stderr,
			"read file error: %s\n",
			strerror(errno));
		return -1;
	}

	rc = gnutls_pkcs7_import(mscat_ctx->pkcs7,
				 &mscat_data,
				 GNUTLS_X509_FMT_DER);
	free(mscat_data.data);
	if (rc < 0) {
		fprintf(stderr,
			"import error: %s\n",
			gnutls_strerror(rc));
		return -1;
	}

	/* TODO verify certificate */

	oid = gnutls_pkcs7_get_embedded_data_oid(mscat_ctx->pkcs7);
	if (oid == NULL) {
		fprintf(stderr,
			"oid error: %s\n",
			strerror(errno));
		return -1;
	}

	cmp = strcmp(oid, PKCS7_CTL_OBJID);
	if (cmp != 0) {
		fprintf(stderr,
			"invalid oid: %s, expected: %s\n",
			oid, PKCS7_CTL_OBJID);
		return -1;
	}
	printf("Micorosoft PKCS7 (%s)\n", oid);

	rc = gnutls_pkcs7_get_embedded_data(mscat_ctx->pkcs7,
					    GNUTLS_PKCS7_EDATA_GET_RAW,
					    &mscat_ctx->mscat_raw_data);
	if (rc < 0) {
		fprintf(stderr,
			"get embedded data error: %s\n",
			strerror(errno));
		return -1;
	}

	return 0;
}

static int mscat_asn1_init_parser(struct mscat_context *mscat_ctx)
{
	char error_string[ASN1_MAX_ERROR_DESCRIPTION_SIZE] = {0};
	int rc;

	rc = asn1_parser2tree("mscat.asn",
			      &mscat_ctx->asn1_desc,
			      error_string);
	if (rc != ASN1_SUCCESS) {
		asn1_perror(rc);
		fprintf(stderr, "asn1_parser2tree: %s\n", error_string);
		return -1;
	}

	return 0;
}

static int mscat_asn1_check_oid(asn1_node root,
				const char *name,
				const char *expected_oid)
{
	char error_string[ASN1_MAX_ERROR_DESCRIPTION_SIZE] = {0};
	char oid[32] = {0};
	int oid_len = sizeof(oid);
	int cmp;
	int rc;

	rc = asn1_read_value(root,
			     name,
			     oid,
			     &oid_len);
	if (rc != ASN1_SUCCESS) {
		asn1_perror(rc);
		fprintf(stderr,
			"asn1_read_value(%s): %s\n",
			name,
			error_string);
		return -1;
	}

	cmp = strcmp(oid, expected_oid);
	if (cmp != 0) {
		fprintf(stderr,
			"Invalid oid: %s, expected: %s\n",
			oid,
			expected_oid);
		return -1;
	}

	return 0;
}

static int mscat_asn1_process_catalog_members(asn1_node root)
{
	char error_string[ASN1_MAX_ERROR_DESCRIPTION_SIZE] = {0};
	int num_members = 0;
	char name[64] = {0};
	uint8_t octet_str[256] = {0};
	int octet_len = sizeof(octet_str);
	int i;
	int rc;

	rc = asn1_number_of_elements(root,
				     "members",
				     &num_members);
	if (rc != ASN1_SUCCESS) {
		asn1_perror(rc);
		fprintf(stderr, "asn1_number_of_elements: %s\n", error_string);
		return -1;
	}

	for (i = 1; i <= num_members; i++) {
		snprintf(name, sizeof(name), "members.?%d.data", i);

		rc = asn1_read_value(root,
				     name,
				     octet_str,
				     &octet_len);
		if (rc != ASN1_SUCCESS) {
			asn1_perror(rc);
			fprintf(stderr,
				"asn1_read_value(%s): %s\n",
				name,
				error_string);
			return -1;
		}

		printf("members[%d].data\n", i);
		dump_data(octet_str, octet_len);

	}

	return 0;
}

static int mscat_asn1_parse_embedded_data(struct mscat_context *mscat_ctx)
{
	char error_string[ASN1_MAX_ERROR_DESCRIPTION_SIZE] = {0};
	ASN1_TYPE cat_ctl = ASN1_TYPE_EMPTY;
	int rc;

	rc = asn1_create_element(mscat_ctx->asn1_desc,
				 "CATALOG.CertTrustList",
				 &cat_ctl);
	if (rc != ASN1_SUCCESS) {
		asn1_perror(rc);
		fprintf(stderr, "asn1_create_element: %s\n", error_string);
		return -1;
	}

	rc = asn1_der_decoding(&cat_ctl,
			       mscat_ctx->mscat_raw_data.data,
			       mscat_ctx->mscat_raw_data.size,
			       error_string);
	if (rc != ASN1_SUCCESS) {
		asn1_perror(rc);
		fprintf(stderr, "asn1_der_decoding: %s\n", error_string);
		return -1;
	}

	rc = mscat_asn1_check_oid(cat_ctl,
				  "catalogListId.oid",
				  CATALOG_LIST_OBJOID);
	if (rc != 0) {
		return -1;
	}

	rc = mscat_asn1_check_oid(cat_ctl,
				  "catalogListMemberId.oid",
				  CATALOG_LIST_MEMBER_OBJOID);
	if (rc != 0) {
		return -1;
	}

	printf("Microsoft Certificate Trust List:\n");

	rc = mscat_asn1_process_catalog_members(cat_ctl);
	if (rc != 0) {
		return -1;
	}

	return 0;
}

int main(int argc, char *argv[]) {
	const char *filename = argv[1];
	struct mscat_context mscat_ctx;
	int rc;

	if (argc < 1) {
		return -1;
	}

	if (filename == NULL || filename[0] == '\0') {
		return -1;
	}

	memset(&mscat_ctx, 0, sizeof(struct mscat_context));

	/* READ MS ROOT CERTIFICATE */

	rc = mscat_import_pkcs7(&mscat_ctx,
				filename);
	if (rc != 0) {
		return -1;
	}

#if 0
	dump_data(mscat_ctx.mscat_raw_data.data,
		  mscat_ctx.mscat_raw_data.size);
#endif

	rc = mscat_asn1_init_parser(&mscat_ctx);
	if (rc != 0) {
		return -1;
	}

	rc = mscat_asn1_parse_embedded_data(&mscat_ctx);
	if (rc != 0) {
		return -1;
	}

	return 0;
}
