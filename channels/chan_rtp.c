/*
 * Asterisk -- An open source telephony toolkit.
 *
 * Copyright (C) 2009 - 2014, Digium, Inc.
 *
 * Joshua Colp <jcolp@digium.com>
 * Andreas 'MacBrody' Brodmann <andreas.brodmann@gmail.com>
 *
 * See http://www.asterisk.org for more information about
 * the Asterisk project. Please do not directly contact
 * any of the maintainers of this project for assistance;
 * the project provides a web site, mailing lists and IRC
 * channels for your use.
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 */

/*! \file
 *
 * \author Joshua Colp <jcolp@digium.com>
 * \author Andreas 'MacBrody' Broadmann <andreas.brodmann@gmail.com>
 *
 * \brief RTP (Multicast and Unicast) Media Channel
 *
 * \ingroup channel_drivers
 */

/*** MODULEINFO
	<depend>res_rtp_multicast</depend>
	<support_level>core</support_level>
 ***/

#include "asterisk.h"

#include "asterisk/channel.h"
#include "asterisk/module.h"
#include "asterisk/pbx.h"
#include "asterisk/acl.h"
#include "asterisk/app.h"
#include "asterisk/rtp_engine.h"
#include "asterisk/causes.h"
#include "asterisk/format_cache.h"
#include "asterisk/format_cap.h"
#include "asterisk/multicast_rtp.h"
#include "asterisk/dns_core.h"

/* Forward declarations */
static struct ast_channel *multicast_rtp_request(const char *type, struct ast_format_cap *cap, const struct ast_assigned_ids *assignedids, const struct ast_channel *requestor, const char *data, int *cause);
static struct ast_channel *unicast_rtp_request(const char *type, struct ast_format_cap *cap, const struct ast_assigned_ids *assignedids, const struct ast_channel *requestor, const char *data, int *cause);
static int rtp_call(struct ast_channel *ast, const char *dest, int timeout);
static int rtp_hangup(struct ast_channel *ast);
static struct ast_frame *rtp_read(struct ast_channel *ast);
static int rtp_write(struct ast_channel *ast, struct ast_frame *f);

/* Multicast channel driver declaration */
static struct ast_channel_tech multicast_rtp_tech = {
	.type = "MulticastRTP",
	.description = "Multicast RTP Paging Channel Driver",
	.requester = multicast_rtp_request,
	.call = rtp_call,
	.hangup = rtp_hangup,
	.read = rtp_read,
	.write = rtp_write,
};

/* Unicast channel driver declaration */
static struct ast_channel_tech unicast_rtp_tech = {
	.type = "UnicastRTP",
	.description = "Unicast RTP Media Channel Driver",
	.requester = unicast_rtp_request,
	.call = rtp_call,
	.hangup = rtp_hangup,
	.read = rtp_read,
	.write = rtp_write,
};

/*! \brief Function called when we should read a frame from the channel */
static struct ast_frame  *rtp_read(struct ast_channel *ast)
{
	struct ast_rtp_instance *instance = ast_channel_tech_pvt(ast);
	int fdno = ast_channel_fdno(ast);

	switch (fdno) {
	case 0:
		return ast_rtp_instance_read(instance, 0);
	default:
		return &ast_null_frame;
	}
}

/*! \brief Function called when we should write a frame to the channel */
static int rtp_write(struct ast_channel *ast, struct ast_frame *f)
{
	struct ast_rtp_instance *instance = ast_channel_tech_pvt(ast);

	return ast_rtp_instance_write(instance, f);
}

/*! \brief Function called when we should actually call the destination */
static int rtp_call(struct ast_channel *ast, const char *dest, int timeout)
{
	struct ast_rtp_instance *instance = ast_channel_tech_pvt(ast);

	ast_queue_control(ast, AST_CONTROL_ANSWER);

	return ast_rtp_instance_activate(instance);
}

/*! \brief Function called when we should hang the channel up */
static int rtp_hangup(struct ast_channel *ast)
{
	struct ast_rtp_instance *instance = ast_channel_tech_pvt(ast);

	ast_rtp_instance_destroy(instance);

	ast_channel_tech_pvt_set(ast, NULL);

	return 0;
}

static struct ast_format *derive_format_from_cap(struct ast_format_cap *cap)
{
	struct ast_format *fmt = ast_format_cap_get_format(cap, 0);

	if (ast_format_cap_count(cap) == 1 && fmt == ast_format_slin) {
		/*
		 * Because we have no SDP, we must use one of the static RTP payload
		 * assignments. Signed linear @ 8kHz does not map, so if that is our
		 * only capability, we force μ-law instead.
		 */
		fmt = ast_format_ulaw;
	}

	return fmt;
}

/*! \brief Function called when we should prepare to call the multicast destination */
static struct ast_channel *multicast_rtp_request(const char *type, struct ast_format_cap *cap, const struct ast_assigned_ids *assignedids, const struct ast_channel *requestor, const char *data, int *cause)
{
	char *parse;
	struct ast_rtp_instance *instance;
	struct ast_sockaddr control_address;
	struct ast_sockaddr destination_address;
	struct ast_channel *chan;
	struct ast_format_cap *caps = NULL;
	struct ast_format *fmt = NULL;
	AST_DECLARE_APP_ARGS(args,
		AST_APP_ARG(type);
		AST_APP_ARG(destination);
		AST_APP_ARG(control);
		AST_APP_ARG(options);
	);
	struct ast_multicast_rtp_options *mcast_options = NULL;

	if (ast_strlen_zero(data)) {
		ast_log(LOG_ERROR, "A multicast type and destination must be given to the 'MulticastRTP' channel\n");
		goto failure;
	}
	parse = ast_strdupa(data);
	AST_NONSTANDARD_APP_ARGS(args, parse, '/');

	if (ast_strlen_zero(args.type)) {
		ast_log(LOG_ERROR, "Type is required for the 'MulticastRTP' channel\n");
		goto failure;
	}

	if (ast_strlen_zero(args.destination)) {
		ast_log(LOG_ERROR, "Destination is required for the 'MulticastRTP' channel\n");
		goto failure;
	}
	if (!ast_sockaddr_parse(&destination_address, args.destination, PARSE_PORT_REQUIRE)) {
		ast_log(LOG_ERROR, "Destination address '%s' could not be parsed\n",
			args.destination);
		goto failure;
	}

	ast_sockaddr_setnull(&control_address);
	if (!ast_strlen_zero(args.control)
		&& !ast_sockaddr_parse(&control_address, args.control, PARSE_PORT_REQUIRE)) {
		ast_log(LOG_ERROR, "Control address '%s' could not be parsed\n", args.control);
		goto failure;
	}

	mcast_options = ast_multicast_rtp_create_options(args.type, args.options);
	if (!mcast_options) {
		goto failure;
	}

	fmt = ast_multicast_rtp_options_get_format(mcast_options);
	if (!fmt) {
		fmt = derive_format_from_cap(cap);
	}
	if (!fmt) {
		ast_log(LOG_ERROR, "No codec available for sending RTP to '%s'\n",
			args.destination);
		goto failure;
	}

	caps = ast_format_cap_alloc(AST_FORMAT_CAP_FLAG_DEFAULT);
	if (!caps) {
		goto failure;
	}

	instance = ast_rtp_instance_new("multicast", NULL, &control_address, mcast_options);
	if (!instance) {
		ast_log(LOG_ERROR,
			"Could not create '%s' multicast RTP instance for sending media to '%s'\n",
			args.type, args.destination);
		goto failure;
	}

	chan = ast_channel_alloc(1, AST_STATE_DOWN, "", "", "", "", "", assignedids,
		requestor, 0, "MulticastRTP/%p", instance);
	if (!chan) {
		ast_rtp_instance_destroy(instance);
		goto failure;
	}
	ast_rtp_instance_set_channel_id(instance, ast_channel_uniqueid(chan));
	ast_rtp_instance_set_remote_address(instance, &destination_address);

	ast_channel_tech_set(chan, &multicast_rtp_tech);

	ast_format_cap_append(caps, fmt, 0);
	ast_channel_nativeformats_set(chan, caps);
	ast_channel_set_writeformat(chan, fmt);
	ast_channel_set_rawwriteformat(chan, fmt);
	ast_channel_set_readformat(chan, fmt);
	ast_channel_set_rawreadformat(chan, fmt);

	ast_channel_tech_pvt_set(chan, instance);

	ast_channel_unlock(chan);

	ao2_ref(fmt, -1);
	ao2_ref(caps, -1);
	ast_multicast_rtp_free_options(mcast_options);

	return chan;

failure:
	ao2_cleanup(fmt);
	ao2_cleanup(caps);
	ast_multicast_rtp_free_options(mcast_options);
	*cause = AST_CAUSE_FAILURE;
	return NULL;
}

enum {
	OPT_RTP_CODEC =  (1 << 0),
	OPT_RTP_ENGINE = (1 << 1),
};

enum {
	OPT_ARG_RTP_CODEC,
	OPT_ARG_RTP_ENGINE,
	/* note: this entry _MUST_ be the last one in the enum */
	OPT_ARG_ARRAY_SIZE
};

AST_APP_OPTIONS(unicast_rtp_options, BEGIN_OPTIONS
	/*! Set the codec to be used for unicast RTP */
	AST_APP_OPTION_ARG('c', OPT_RTP_CODEC, OPT_ARG_RTP_CODEC),
	/*! Set the RTP engine to use for unicast RTP */
	AST_APP_OPTION_ARG('e', OPT_RTP_ENGINE, OPT_ARG_RTP_ENGINE),
END_OPTIONS );

/*! \brief Function called when we should prepare to call the unicast destination */
static struct ast_channel *unicast_rtp_request(const char *type, struct ast_format_cap *cap, const struct ast_assigned_ids *assignedids, const struct ast_channel *requestor, const char *data, int *cause)
{
	char *parse;
	struct ast_rtp_instance *instance;
	struct ast_sockaddr address;
	struct ast_sockaddr local_address;
	struct ast_channel *chan;
	struct ast_format_cap *caps = NULL;
	struct ast_format *fmt = NULL;
	struct ast_rtp_codecs codecs = AST_RTP_CODECS_NULL_INIT;

	const char *engine_name;
	AST_DECLARE_APP_ARGS(args,
		AST_APP_ARG(destination);
		AST_APP_ARG(options);
	);
	struct ast_flags opts = { 0, };
	char *opt_args[OPT_ARG_ARRAY_SIZE];

	if (ast_strlen_zero(data)) {
		ast_log(LOG_ERROR, "Destination is required for the 'UnicastRTP' channel\n");
		goto failure;
	}
	parse = ast_strdupa(data);
	AST_NONSTANDARD_APP_ARGS(args, parse, '/');

	if (ast_strlen_zero(args.destination)) {
		ast_log(LOG_ERROR, "Destination is required for the 'UnicastRTP' channel\n");
		goto failure;
	}

	if (!ast_sockaddr_parse(&address, args.destination, PARSE_PORT_REQUIRE)) {
	    int rc;
	    char *host;
	    char *port;

	    rc = ast_sockaddr_split_hostport(args.destination, &host, &port, PARSE_PORT_REQUIRE);
	    if (!rc) {
	        ast_log(LOG_ERROR, "Unable to parse destination '%s' into host and port\n", args.destination);
	        goto failure;
	    }

	    rc = ast_dns_resolve_ipv6_and_ipv4(&address, host, port);
	    if (rc != 0) {
	        ast_log(LOG_ERROR, "Unable to resolve host '%s'\n", host);
	        goto failure;
	    }
	}

	if (!ast_strlen_zero(args.options)
		&& ast_app_parse_options(unicast_rtp_options, &opts, opt_args,
			ast_strdupa(args.options))) {
		ast_log(LOG_ERROR, "'UnicastRTP' channel options '%s' parse error\n",
			args.options);
		goto failure;
	}

	ast_debug(1, "'UnicastRTP' channel options '%s' parsed\n", args.options);

	if (ast_test_flag(&opts, OPT_RTP_CODEC)
		&& !ast_strlen_zero(opt_args[OPT_ARG_RTP_CODEC])) {
		fmt = ast_format_cache_get(opt_args[OPT_ARG_RTP_CODEC]);
		ast_debug(1, "Codec '%s' found for sending RTP to '%s'\n", opt_args[OPT_ARG_RTP_CODEC], args.destination);
		if (!fmt) {
			ast_log(LOG_ERROR, "Codec '%s' not found for sending RTP to '%s'\n",
				opt_args[OPT_ARG_RTP_CODEC], args.destination);
			goto failure;
		}
	} else {
		fmt = derive_format_from_cap(cap);
		ast_debug(1, "No codec option for sending RTP to '%s', using derive_format_from_cap(cap)\n", args.destination);
		if (!fmt) {
			ast_log(LOG_ERROR, "No codec available for sending RTP to '%s'\n",
				args.destination);
			goto failure;
		}
	}

	caps = ast_format_cap_alloc(AST_FORMAT_CAP_FLAG_DEFAULT);
	if (!caps) {
		goto failure;
	}

	engine_name = S_COR(ast_test_flag(&opts, OPT_RTP_ENGINE),
		opt_args[OPT_ARG_RTP_ENGINE], "asterisk");

	ast_sockaddr_copy(&local_address, &address);
	if (ast_ouraddrfor(&address, &local_address)) {
		ast_log(LOG_ERROR, "Could not get our address for sending media to '%s'\n",
			args.destination);
		goto failure;
	}
	instance = ast_rtp_instance_new(engine_name, NULL, &local_address, NULL);
	if (!instance) {
		ast_log(LOG_ERROR,
			"Could not create %s RTP instance for sending media to '%s'\n",
			S_OR(engine_name, "default"), args.destination);
		goto failure;
	}

	chan = ast_channel_alloc(1, AST_STATE_DOWN, "", "", "", "", "", assignedids,
		requestor, 0, "UnicastRTP/%s-%p", args.destination, instance);
	if (!chan) {
		ast_rtp_instance_destroy(instance);
		goto failure;
	}
	ast_rtp_instance_set_channel_id(instance, ast_channel_uniqueid(chan));
	ast_rtp_instance_set_remote_address(instance, &address);
	ast_channel_set_fd(chan, 0, ast_rtp_instance_fd(instance, 0));

	ast_channel_tech_set(chan, &unicast_rtp_tech);

	ast_format_cap_append(caps, fmt, 0);

	/* ADD YOUR CODE HERE */

	/* CREATE CODECS */
	// Step #1 Get the Asterisk payload type
	int payload_type;
	payload_type = ast_rtp_codecs_payload_code(ast_rtp_instance_get_codecs(instance), 1, fmt, 0);
	ast_rtp_codecs_payload_set_rx(ast_rtp_instance_get_codecs(instance), payload_type, fmt);
	ast_debug(1, "UnicastRTP/%s-%p payload type set %d\n", args.destination, instance, rtp_code);
	// Step #2. Record tx payload type information that was seen in an m= SDP line.
	ast_rtp_codecs_payloads_set_m_type(codecs, instance, payload_type);
	// Step #3. Set tx payload type to a known MIME media type for a codec with a specific sample rate.
	ast_rtp_codecs_payloads_set_rtpmap_type_rate(codecs, instance, payload_type, "audio", "opus", 0, 48000)

	// 2. Set framing
	ast_format_cap_set_framing(caps, codecs);
	// 3. Set codec rtp payloads.
	ast_rtp_codecs_payloads_xover(&codecs, &codecs, NULL); // XXX DOUBLE CHECK
	ast_rtp_codecs_payloads_copy(&codecs, ast_rtp_instance_get_codecs(instance), instance);

	ast_debug(1, "UnicastRTP/%s-%p codec created '%s'\n", 
		args.destination, instance, ast_format_get_codec_name(fmt));

	ast_rtp_codecs_payloads_destroy(&codecs);
	// ast_rtp_codecs_payloads_set_m_type(ast_rtp_instance_get_codecs(sub->rtp), sub->rtp, codec);
	// ast_rtp_codecs_payloads_set_rtpmap_type(ast_rtp_instance_get_codecs(sub->rtp), sub->rtp, codec, "audio", mimeSubtype, 0);
	// ast_rtp_codecs_payload_formats(ast_rtp_instance_get_codecs(sub->rtp), peercap, &peerNonCodecCapability);

	/* END OF NEW CODE*/

	ast_channel_nativeformats_set(chan, caps);
	ast_channel_set_writeformat(chan, fmt);
	ast_channel_set_rawwriteformat(chan, fmt);
	ast_channel_set_readformat(chan, fmt);
	ast_channel_set_rawreadformat(chan, fmt);

	ast_channel_tech_pvt_set(chan, instance);

	pbx_builtin_setvar_helper(chan, "UNICASTRTP_LOCAL_ADDRESS",
		ast_sockaddr_stringify_addr(&local_address));
	ast_rtp_instance_get_local_address(instance, &local_address);
	pbx_builtin_setvar_helper(chan, "UNICASTRTP_LOCAL_PORT",
		ast_sockaddr_stringify_port(&local_address));

	ast_channel_unlock(chan);

	ao2_ref(fmt, -1);
	ao2_ref(caps, -1);

	return chan;

failure:
	ao2_cleanup(fmt);
	ao2_cleanup(caps);
	*cause = AST_CAUSE_FAILURE;
	return NULL;
}


// static void get_codecs(struct ast_sip_session *session, const struct pjmedia_sdp_media *stream, struct ast_rtp_codecs *codecs,
// 	struct ast_sip_session_media *session_media)
// {
// 	pjmedia_sdp_attr *attr;
// 	pjmedia_sdp_rtpmap *rtpmap;
// 	pjmedia_sdp_fmtp fmtp;
// 	struct ast_format *format;
// 	int i, num = 0, tel_event = 0;
// 	char name[256];
// 	char media[20];
// 	char fmt_param[256];
// 	enum ast_rtp_options options = session->endpoint->media.g726_non_standard ?
// 		AST_RTP_OPT_G726_NONSTANDARD : 0;

// 	ast_rtp_codecs_payloads_initialize(codecs);

// 	/* Iterate through provided formats */
// 	for (i = 0; i < stream->desc.fmt_count; ++i) {
// 		/* The payload is kept as a string for things like t38 but for video it is always numerical */
// 		ast_rtp_codecs_payloads_set_m_type(codecs, NULL, pj_strtoul(&stream->desc.fmt[i]));
// 		/* Look for the optional rtpmap attribute */
// 		if (!(attr = pjmedia_sdp_media_find_attr2(stream, "rtpmap", &stream->desc.fmt[i]))) {
// 			continue;
// 		}

// 		/* Interpret the attribute as an rtpmap */
// 		if ((pjmedia_sdp_attr_to_rtpmap(session->inv_session->pool_prov, attr, &rtpmap)) != PJ_SUCCESS) {
// 			continue;
// 		}

// 		ast_copy_pj_str(name, &rtpmap->enc_name, sizeof(name));
// 		if (strcmp(name, "telephone-event") == 0) {
// 			tel_event++;
// 		}

// 		ast_copy_pj_str(media, (pj_str_t*)&stream->desc.media, sizeof(media));
// 		ast_rtp_codecs_payloads_set_rtpmap_type_rate(codecs, NULL,
// 			pj_strtoul(&stream->desc.fmt[i]), media, name, options, rtpmap->clock_rate);
// 		/* Look for an optional associated fmtp attribute */
// 		if (!(attr = pjmedia_sdp_media_find_attr2(stream, "fmtp", &rtpmap->pt))) {
// 			continue;
// 		}

// 		if ((pjmedia_sdp_attr_get_fmtp(attr, &fmtp)) == PJ_SUCCESS) {
// 			ast_copy_pj_str(fmt_param, &fmtp.fmt, sizeof(fmt_param));
// 			if (sscanf(fmt_param, "%30d", &num) != 1) {
// 				continue;
// 			}

// 			if ((format = ast_rtp_codecs_get_payload_format(codecs, num))) {
// 				struct ast_format *format_parsed;

// 				ast_copy_pj_str(fmt_param, &fmtp.fmt_param, sizeof(fmt_param));

// 				format_parsed = ast_format_parse_sdp_fmtp(format, fmt_param);
// 				if (format_parsed) {
// 					ast_rtp_codecs_payload_replace_format(codecs, num, format_parsed);
// 					ao2_ref(format_parsed, -1);
// 				}

// 				ao2_ref(format, -1);
// 			}
// 		}
// 	}
// 	if (!tel_event && (session->dtmf == AST_SIP_DTMF_AUTO)) {
// 		ast_rtp_instance_dtmf_mode_set(session_media->rtp, AST_RTP_DTMF_MODE_INBAND);
// 	}

// 	if (session->dtmf == AST_SIP_DTMF_AUTO_INFO) {
// 		if  (tel_event) {
// 			ast_rtp_instance_dtmf_mode_set(session_media->rtp, AST_RTP_DTMF_MODE_RFC2833);
// 		} else {
// 			ast_rtp_instance_dtmf_mode_set(session_media->rtp, AST_RTP_DTMF_MODE_NONE);
// 		}
// 	}


// 	/* Get the packetization, if it exists */
// 	if ((attr = pjmedia_sdp_media_find_attr2(stream, "ptime", NULL))) {
// 		unsigned long framing = pj_strtoul(pj_strltrim(&attr->value));
// 		if (framing && session->endpoint->media.rtp.use_ptime) {
// 			ast_rtp_codecs_set_framing(codecs, framing);
// 		}
// 	}
// }


// /* channel is already locked */
// static int set_caps(struct ast_channel *chan, struct ast_format *preferred_fmt, 
// 					struct ast_format_cap *caps, struct ast_rtp_codecs *codecs, struct ast_rtp_instance *rtp)
// {

// 	enum ast_media_type media_type = session_media->type;
// 	int fmts = 0;

// 	/* SET FRAMING */
// 	ast_format_cap_set_framing(caps, codecs);

// 	// /* Set frame packetization */
// 	// ast_rtp_codecs_set_framing(ast_rtp_instance_get_codecs(sub->rtp),
// 	// 	ast_format_cap_get_framing(l->cap));

// 	// We use always the same offer.
// 	ast_rtp_codecs_payloads_xover(&codecs, &codecs, NULL);

// 	ast_rtp_codecs_payloads_copy(&codecs, ast_rtp_instance_get_codecs(rtp), rtp);

// 	ast_rtp_codecs_payloads_destroy(&codecs);
// 	return 0;
// }

/*! \brief Function called when our module is unloaded */
static int unload_module(void)
{
	ast_channel_unregister(&multicast_rtp_tech);
	ao2_cleanup(multicast_rtp_tech.capabilities);
	multicast_rtp_tech.capabilities = NULL;

	ast_channel_unregister(&unicast_rtp_tech);
	ao2_cleanup(unicast_rtp_tech.capabilities);
	unicast_rtp_tech.capabilities = NULL;

	return 0;
}

/*! \brief Function called when our module is loaded */
static int load_module(void)
{
	if (!(multicast_rtp_tech.capabilities = ast_format_cap_alloc(AST_FORMAT_CAP_FLAG_DEFAULT))) {
		return AST_MODULE_LOAD_DECLINE;
	}
	ast_format_cap_append_by_type(multicast_rtp_tech.capabilities, AST_MEDIA_TYPE_UNKNOWN);
	if (ast_channel_register(&multicast_rtp_tech)) {
		ast_log(LOG_ERROR, "Unable to register channel class 'MulticastRTP'\n");
		unload_module();
		return AST_MODULE_LOAD_DECLINE;
	}

	if (!(unicast_rtp_tech.capabilities = ast_format_cap_alloc(AST_FORMAT_CAP_FLAG_DEFAULT))) {
		unload_module();
		return AST_MODULE_LOAD_DECLINE;
	}
	ast_format_cap_append_by_type(unicast_rtp_tech.capabilities, AST_MEDIA_TYPE_UNKNOWN);
	if (ast_channel_register(&unicast_rtp_tech)) {
		ast_log(LOG_ERROR, "Unable to register channel class 'UnicastRTP'\n");
		unload_module();
		return AST_MODULE_LOAD_DECLINE;
	}

	return AST_MODULE_LOAD_SUCCESS;
}

AST_MODULE_INFO(ASTERISK_GPL_KEY, AST_MODFLAG_LOAD_ORDER, "RTP Media Channel",
	.support_level = AST_MODULE_SUPPORT_CORE,
	.load = load_module,
	.unload = unload_module,
	.load_pri = AST_MODPRI_CHANNEL_DRIVER,
	.requires = "res_rtp_multicast",
);



// /* channel is already locked */
// static int set_caps(struct ast_channel *chan, struct ast_format *preferred_fmt,
// 	const struct pjmedia_sdp_media *stream,
// 	struct ast_stream *asterisk_stream)
// {
// 	RAII_VAR(struct ast_format_cap *, caps, NULL, ao2_cleanup);
// 	// RAII_VAR(struct ast_format_cap *, peer, NULL, ao2_cleanup);
// 	// RAII_VAR(struct ast_format_cap *, joint, NULL, ao2_cleanup);
// 	enum ast_media_type media_type = session_media->type;
// 	struct ast_rtp_codecs codecs = AST_RTP_CODECS_NULL_INIT;
// 	int fmts = 0;
// 	// int direct_media_enabled = !ast_sockaddr_isnull(&session_media->direct_media_addr) &&
// 	// 	ast_format_cap_count(session->direct_media_cap);
// 	// int dsp_features = 0;

// 	// if (!(caps = ast_format_cap_alloc(AST_FORMAT_CAP_FLAG_DEFAULT)) ||
// 	//     !(peer = ast_format_cap_alloc(AST_FORMAT_CAP_FLAG_DEFAULT)) ||
// 	//     !(joint = ast_format_cap_alloc(AST_FORMAT_CAP_FLAG_DEFAULT))) {
// 	// 	ast_log(LOG_ERROR, "Failed to allocate %s capabilities\n",
// 	// 		ast_codec_media_type2str(session_media->type));
// 	// 	return -1;
// 	// }
// channel
// 	/* get the endpoint capabilities */
// 	/* Direct media is not allowed in UnicastRTP */
// 	ast_format_cap_append_from_cap(caps, session->endpoint->media.codecs, media_type);

// 	// /* get the capabilities on the peer */
// 	// get_codecs(session, stream, &codecs,  session_media);
// 	// ast_rtp_codecs_payload_formats(&codecs, peer, &fmts);

// 	// /* get the joint capabilities between peer and endpoint */
// 	// ast_format_cap_get_compatible(caps, peer, joint);
// 	// if (!ast_format_cap_count(joint)) {
// 	// 	struct ast_str *usbuf = ast_str_alloca(AST_FORMAT_CAP_NAMES_LEN);
// 	// 	struct ast_str *thembuf = ast_str_alloca(AST_FORMAT_CAP_NAMES_LEN);

// 	// 	ast_rtp_codecs_payloads_destroy(&codecs);
// 	// 	ast_log(LOG_NOTICE, "No joint capabilities for '%s' media stream between our configuration(%s) and incoming SDP(%s)\n",
// 	// 		ast_codec_media_type2str(session_media->type),
// 	// 		ast_format_cap_get_names(caps, &usbuf),
// 	// 		ast_format_cap_get_names(peer, &thembuf));
// 	// 	return -1;
// 	// }

// 	// We use always the same offer.
// 	// if (is_offer) {
// 		/*
// 		 * Setup rx payload type mapping to prefer the mapping
// 		 * from the peer that the RFC says we SHOULD use.
// 		 */
// 		ast_rtp_codecs_payloads_xover(&codecs, &codecs, NULL);
// 	// }
// 	ast_rtp_codecs_payloads_copy(&codecs, ast_rtp_instance_get_codecs(session_media->rtp),
// 		session_media->rtp);

// 	ast_stream_set_formats(asterisk_stream, joint);

// 	// /* If this is a bundled stream then apply the payloads to RTP instance acting as transport to prevent conflicts */
// 	// if (session_media_transport != session_media && session_media->bundled) {
// 	// 	int index;

// 	// 	for (index = 0; index < ast_format_cap_count(joint); ++index) {
// 	// 		struct ast_format *format = ast_format_cap_get_format(joint, index);
// 	// 		int rtp_code;

// 	// 		/* Ensure this payload is in the bundle group transport codecs, this purposely doesn't check the return value for
// 	// 		 * things as the format is guaranteed to have a payload already.
// 	// 		 */
// 	// 		rtp_code = ast_rtp_codecs_payload_code(ast_rtp_instance_get_codecs(session_media->rtp), 1, format, 0);
// 	// 		ast_rtp_codecs_payload_set_rx(ast_rtp_instance_get_codecs(session_media_transport->rtp), rtp_code, format);

// 	// 		ao2_ref(format, -1);
// 	// 	}
// 	// }


// 	// channel is already locked
// 	// ast_channel_lock(chan);
// 	ast_format_cap_remove_by_type(caps, AST_MEDIA_TYPE_UNKNOWN);
// 	ast_format_cap_append_from_cap(caps, ast_channel_nativeformats(chan),
// 		AST_MEDIA_TYPE_UNKNOWN);
// 	ast_format_cap_remove_by_type(caps, media_type);

// 	/* USE preferred_codec_only CODE */
// 	// struct ast_format *preferred_fmt = ast_format_cap_get_format(joint, 0);
// 	ast_format_cap_append(caps, preferred_fmt, 0);
// 	// ao2_ref(preferred_fmt, -1);

// 	// if (chan && ast_sip_session_is_pending_stream_default(session, asterisk_stream)) {
// 	// 	ast_channel_lock(chan);
// 	// 	ast_format_cap_remove_by_type(caps, AST_MEDIA_TYPE_UNKNOWN);
// 	// 	ast_format_cap_append_from_cap(caps, ast_channel_nativeformats(chan),
// 	// 		AST_MEDIA_TYPE_UNKNOWN);
// 	// 	ast_format_cap_remove_by_type(caps, media_type);

// 	// 	/* USE preferred_codec_only CODE */
// 	// 	struct ast_format *preferred_fmt = ast_format_cap_get_format(joint, 0);
// 	// 	ast_format_cap_append(caps, preferred_fmt, 0);
// 	// 	ao2_ref(preferred_fmt, -1);

// 	// 	// if (session->endpoint->preferred_codec_only){
// 	// 	// 	struct ast_format *preferred_fmt = ast_format_cap_get_format(joint, 0);
// 	// 	// 	ast_format_cap_append(caps, preferred_fmt, 0);
// 	// 	// 	ao2_ref(preferred_fmt, -1);
// 	// 	// } else if (!session->endpoint->asymmetric_rtp_codec) {
// 	// 	// 	struct ast_format *best;
// 	// 	// 	/*
// 	// 	// 	 * If we don't allow the sending codec to be changed on our side
// 	// 	// 	 * then get the best codec from the joint capabilities of the media
// 	// 	// 	 * type and use only that. This ensures the core won't start sending
// 	// 	// 	 * out a format that we aren't currently sending.
// 	// 	// 	 */

// 	// 	// 	best = ast_format_cap_get_best_by_type(joint, media_type);
// 	// 	// 	if (best) {
// 	// 	// 		ast_format_cap_append(caps, best, ast_format_cap_get_framing(joint));
// 	// 	// 		ao2_ref(best, -1);
// 	// 	// 	}
// 	// 	// } else {
// 	// 	// 	ast_format_cap_append_from_cap(caps, joint, media_type);
// 	// 	// }

// 	// 	/* THIS WAS ALREADY DONE WHEN CREATING THE RTP INSTANCE */
// 	// 	// /*
// 	// 	//  * Apply the new formats to the channel, potentially changing
// 	// 	//  * raw read/write formats and translation path while doing so.
// 	// 	//  */
// 	// 	// ast_channel_nativeformats_set(chan, caps);
// 	// 	// if (media_type == AST_MEDIA_TYPE_AUDIO) {
// 	// 	// 	ast_set_read_format(chan, ast_channel_readformat(chan));
// 	// 	// 	ast_set_write_format(chan, ast_channel_writeformat(chan));
// 	// 	// }

// 	// 	/* DTMF IS NOT SUPPORTED IN UNICAST RTP */
// 	// 	// if ( ((session->dtmf == AST_SIP_DTMF_AUTO) || (session->dtmf == AST_SIP_DTMF_AUTO_INFO) )
// 	// 	//     && (ast_rtp_instance_dtmf_mode_get(session_media->rtp) == AST_RTP_DTMF_MODE_RFC2833)
// 	// 	//     && (session->dsp)) {
// 	// 	// 	dsp_features = ast_dsp_get_features(session->dsp);
// 	// 	// 	dsp_features &= ~DSP_FEATURE_DIGIT_DETECT;
// 	// 	// 	if (dsp_features) {
// 	// 	// 		ast_dsp_set_features(session->dsp, dsp_features);
// 	// 	// 	} else {
// 	// 	// 		ast_dsp_free(session->dsp);
// 	// 	// 		session->dsp = NULL;
// 	// 	// 	}
// 	// 	// }

// 	// 	/* CHECK BRIDGE AND CHANNEL LOCKS */

// 	// 	if (ast_channel_is_bridged(chan)) {
// 	// 		ast_channel_set_unbridged_nolock(chan, 1);
// 	// 	}

// 	// 	ast_channel_unlock(chan);
// 	// }

// 	ast_rtp_codecs_payloads_destroy(&codecs);
// 	return 0;
// }
