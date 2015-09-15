/**
 * Copyright (c) 2006-2010 Apple Inc. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 **/

#include "kerberosgss.h"

#include "base64.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

static void set_gss_error(OM_uint32 err_maj, OM_uint32 err_min);

/*extern PyObject *GssException_class;
extern PyObject *KrbException_class;

char* server_principal_details(const char* service, const char* hostname)
{
    char match[1024];
    int match_len = 0;
    char* result = NULL;
    
    int code;
    krb5_context kcontext;
    krb5_keytab kt = NULL;
    krb5_kt_cursor cursor = NULL;
    krb5_keytab_entry entry;
    char* pname = NULL;
    
    // Generate the principal prefix we want to match
    snprintf(match, 1024, "%s/%s@", service, hostname);
    match_len = strlen(match);
    
    code = krb5_init_context(&kcontext);
    if (code)
    {
        PyErr_SetObject(KrbException_class, Py_BuildValue("((s:i))",
                                                          "Cannot initialize Kerberos5 context", code));
        return NULL;
    }
    
    if ((code = krb5_kt_default(kcontext, &kt)))
    {
        PyErr_SetObject(KrbException_class, Py_BuildValue("((s:i))",
                                                          "Cannot get default keytab", code));
        goto end;
    }
    
    if ((code = krb5_kt_start_seq_get(kcontext, kt, &cursor)))
    {
        PyErr_SetObject(KrbException_class, Py_BuildValue("((s:i))",
                                                          "Cannot get sequence cursor from keytab", code));
        goto end;
    }
    
    while ((code = krb5_kt_next_entry(kcontext, kt, &entry, &cursor)) == 0)
    {
        if ((code = krb5_unparse_name(kcontext, entry.principal, &pname)))
        {
            PyErr_SetObject(KrbException_class, Py_BuildValue("((s:i))",
                                                              "Cannot parse principal name from keytab", code));
            goto end;
        }
        
        if (strncmp(pname, match, match_len) == 0)
        {
            result = malloc(strlen(pname) + 1);
            strcpy(result, pname);
            krb5_free_unparsed_name(kcontext, pname);
            krb5_free_keytab_entry_contents(kcontext, &entry);
            break;
        }
        
        krb5_free_unparsed_name(kcontext, pname);
        krb5_free_keytab_entry_contents(kcontext, &entry);
    }
    
    if (result == NULL)
    {
        PyErr_SetObject(KrbException_class, Py_BuildValue("((s:i))",
                                                          "Principal not found in keytab", -1));
    }
    
end:
    if (cursor)
        krb5_kt_end_seq_get(kcontext, kt, &cursor);
    if (kt)
        krb5_kt_close(kcontext, kt);
    krb5_free_context(kcontext);
    
    return result;
}
*/
gss_client_response *authenticate_gss_client_init(const char* service, long int gss_flags, gss_client_state* state) {
  OM_uint32 maj_stat;
  OM_uint32 min_stat;
  gss_buffer_desc name_token = GSS_C_EMPTY_BUFFER;
  gss_client_response *response = NULL;
  int ret = AUTH_GSS_COMPLETE;

  state->server_name = GSS_C_NO_NAME;
  state->context = GSS_C_NO_CONTEXT;
  state->gss_flags = gss_flags;
  state->username = NULL;
  state->response = NULL;
  
  // Import server name first
  name_token.length = strlen(service);
  name_token.value = (char *)service;
  
  maj_stat = gss_import_name(&min_stat, &name_token, gss_krb5_nt_service_name, &state->server_name);
  
  if (GSS_ERROR(maj_stat)) {
    response = gss_error(maj_stat, min_stat);
    response->return_code = AUTH_GSS_ERROR;
    goto end;
  }
  
end:
  if(response == NULL) {
    response = calloc(1, sizeof(gss_client_response));
    response->return_code = ret;    
  }

  return response;
}

gss_client_response *authenticate_gss_client_clean(gss_client_state *state) {
  OM_uint32 min_stat;
  int ret = AUTH_GSS_COMPLETE;
  gss_client_response *response = NULL;
  
  if(state->context != GSS_C_NO_CONTEXT)
    gss_delete_sec_context(&min_stat, &state->context, GSS_C_NO_BUFFER);
  
  if(state->server_name != GSS_C_NO_NAME)
    gss_release_name(&min_stat, &state->server_name);
  
  if(state->username != NULL) {
    free(state->username);
    state->username = NULL;
  }

  if (state->response != NULL) {
    free(state->response);
    state->response = NULL;
  }
  
  if(response == NULL) {
    response = calloc(1, sizeof(gss_client_response));
    response->return_code = ret;    
  }

  return response;
}

gss_client_response *authenticate_gss_client_step(gss_client_state* state, const char* challenge) {
  OM_uint32 maj_stat;
  OM_uint32 min_stat;
  gss_buffer_desc input_token = GSS_C_EMPTY_BUFFER;
  gss_buffer_desc output_token = GSS_C_EMPTY_BUFFER;
  int ret = AUTH_GSS_CONTINUE;
  gss_client_response *response = NULL;
  
  // Always clear out the old response
  if (state->response != NULL) {
    free(state->response);
    state->response = NULL;
  }
  
  // If there is a challenge (data from the server) we need to give it to GSS
  if (challenge && *challenge) {
    int len;
    input_token.value = base64_decode(challenge, &len);
    input_token.length = len;
  }
  
  // Do GSSAPI step
  maj_stat = gss_init_sec_context(&min_stat,
                                  GSS_C_NO_CREDENTIAL,
                                  &state->context,
                                  state->server_name,
                                  GSS_C_NO_OID,
                                  (OM_uint32)state->gss_flags,
                                  0,
                                  GSS_C_NO_CHANNEL_BINDINGS,
                                  &input_token,
                                  NULL,
                                  &output_token,
                                  NULL,
                                  NULL);

  if ((maj_stat != GSS_S_COMPLETE) && (maj_stat != GSS_S_CONTINUE_NEEDED)) {
    response = gss_error(maj_stat, min_stat);
    response->return_code = AUTH_GSS_ERROR;
    goto end;
  }
  
  ret = (maj_stat == GSS_S_COMPLETE) ? AUTH_GSS_COMPLETE : AUTH_GSS_CONTINUE;
  // Grab the client response to send back to the server
  if(output_token.length) {
    state->response = base64_encode((const unsigned char *)output_token.value, output_token.length);
    maj_stat = gss_release_buffer(&min_stat, &output_token);
  }
  
  // Try to get the user name if we have completed all GSS operations
  if (ret == AUTH_GSS_COMPLETE) {
    gss_name_t gssuser = GSS_C_NO_NAME;
    maj_stat = gss_inquire_context(&min_stat, state->context, &gssuser, NULL, NULL, NULL,  NULL, NULL, NULL);
    
    if(GSS_ERROR(maj_stat)) {
      response = gss_error(maj_stat, min_stat);
      response->return_code = AUTH_GSS_ERROR;
      goto end;
    }
    
    gss_buffer_desc name_token;
    name_token.length = 0;
    maj_stat = gss_display_name(&min_stat, gssuser, &name_token, NULL);
    
    if(GSS_ERROR(maj_stat)) {
      if(name_token.value)
        gss_release_buffer(&min_stat, &name_token);
      gss_release_name(&min_stat, &gssuser);
      
      response = gss_error(maj_stat, min_stat);
      response->return_code = AUTH_GSS_ERROR;
      goto end;
    } else {
      state->username = (char *)malloc(name_token.length + 1);
      strncpy(state->username, (char*) name_token.value, name_token.length);
      state->username[name_token.length] = 0;
      gss_release_buffer(&min_stat, &name_token);
      gss_release_name(&min_stat, &gssuser);
    }
  }

end:
  if(output_token.value)
    gss_release_buffer(&min_stat, &output_token);
  if(input_token.value)
    free(input_token.value);

  if(response == NULL) {
    response = calloc(1, sizeof(gss_client_response));
    response->return_code = ret;
  }

  // Return the response
  return response;
}

gss_client_response *authenticate_gss_client_unwrap(gss_client_state *state, const char *challenge) {
  OM_uint32 maj_stat;
  OM_uint32 min_stat;
  gss_buffer_desc input_token = GSS_C_EMPTY_BUFFER;
  gss_buffer_desc output_token = GSS_C_EMPTY_BUFFER;
  gss_client_response *response = NULL;
  int ret = AUTH_GSS_CONTINUE;
    
  // Always clear out the old response
  if(state->response != NULL) {
    free(state->response);
    state->response = NULL;
  }
    
  // If there is a challenge (data from the server) we need to give it to GSS
  if(challenge && *challenge) {
    int len;
    input_token.value = base64_decode(challenge, &len);
    input_token.length = len;
  }
    
  // Do GSSAPI step
  maj_stat = gss_unwrap(&min_stat,
                          state->context,
                          &input_token,
                          &output_token,
                          NULL,
                          NULL);
    
  if(maj_stat != GSS_S_COMPLETE) {
    response = gss_error(maj_stat, min_stat);
    response->return_code = AUTH_GSS_ERROR;
    goto end;
  } else {
    ret = AUTH_GSS_COMPLETE;    
  }
    
  // Grab the client response
  if(output_token.length) {
    state->response = base64_encode((const unsigned char *)output_token.value, output_token.length);
    maj_stat = gss_release_buffer(&min_stat, &output_token);
  }
end:
  if(output_token.value)
    gss_release_buffer(&min_stat, &output_token);
  if(input_token.value)
    free(input_token.value);

  if(response == NULL) {
    response = calloc(1, sizeof(gss_client_response));
    response->return_code = ret;
  }

  // Return the response
  return response;
}

gss_client_response *authenticate_gss_client_wrap(gss_client_state* state, const char* challenge, const char* user) {
  OM_uint32 maj_stat;
  OM_uint32 min_stat;
  gss_buffer_desc input_token = GSS_C_EMPTY_BUFFER;
  gss_buffer_desc output_token = GSS_C_EMPTY_BUFFER;
  int ret = AUTH_GSS_CONTINUE;
  gss_client_response *response = NULL;
  char buf[4096], server_conf_flags;
  unsigned long buf_size;
    
  // Always clear out the old response
  if(state->response != NULL) {
    free(state->response);
    state->response = NULL;
  }
    
  if(challenge && *challenge) {
    int len;
    input_token.value = base64_decode(challenge, &len);
    input_token.length = len;
  }
    
  if(user) {
    // get bufsize
    server_conf_flags = ((char*) input_token.value)[0];
    ((char*) input_token.value)[0] = 0;
    buf_size = ntohl(*((long *) input_token.value));
    free(input_token.value);
#ifdef PRINTFS
    printf("User: %s, %c%c%c\n", user,
               server_conf_flags & GSS_AUTH_P_NONE      ? 'N' : '-',
               server_conf_flags & GSS_AUTH_P_INTEGRITY ? 'I' : '-',
               server_conf_flags & GSS_AUTH_P_PRIVACY   ? 'P' : '-');
    printf("Maximum GSS token size is %ld\n", buf_size);
#endif
        
    // agree to terms (hack!)
    buf_size = htonl(buf_size); // not relevant without integrity/privacy
    memcpy(buf, &buf_size, 4);
    buf[0] = GSS_AUTH_P_NONE;
    // server decides if principal can log in as user
    strncpy(buf + 4, user, sizeof(buf) - 4);
    input_token.value = buf;
    input_token.length = 4 + strlen(user);
  }
    
  // Do GSSAPI wrap
  maj_stat = gss_wrap(&min_stat,
            state->context,
            0,
            GSS_C_QOP_DEFAULT,
            &input_token,
            NULL,
            &output_token);
    
  if (maj_stat != GSS_S_COMPLETE) {
    response = gss_error(maj_stat, min_stat);
    response->return_code = AUTH_GSS_ERROR;
    goto end;
  } else
    ret = AUTH_GSS_COMPLETE;
  // Grab the client response to send back to the server
  if (output_token.length) {
    state->response = base64_encode((const unsigned char *)output_token.value, output_token.length);;
    maj_stat = gss_release_buffer(&min_stat, &output_token);
  }
end:
  if (output_token.value)
    gss_release_buffer(&min_stat, &output_token);

  if(response == NULL) {
    response = calloc(1, sizeof(gss_client_response));
    response->return_code = ret;
  }

  // Return the response
  return response;
}

int authenticate_gss_server_init(const char *service, gss_server_state *state)
{
    OM_uint32 maj_stat;
    OM_uint32 min_stat;
    gss_buffer_desc name_token = GSS_C_EMPTY_BUFFER;
    int ret = AUTH_GSS_COMPLETE;
    
    state->context = GSS_C_NO_CONTEXT;
    state->server_name = GSS_C_NO_NAME;
    state->client_name = GSS_C_NO_NAME;
    state->server_creds = GSS_C_NO_CREDENTIAL;
    state->client_creds = GSS_C_NO_CREDENTIAL;
    state->username = NULL;
    state->targetname = NULL;
    state->response = NULL;
    
    // Server name may be empty which means we aren't going to create our own creds
    size_t service_len = strlen(service);
    if (service_len != 0)
    {
        // Import server name first
        name_token.length = strlen(service);
        name_token.value = (char *)service;
        
        maj_stat = gss_import_name(&min_stat, &name_token, GSS_C_NT_HOSTBASED_SERVICE, &state->server_name);
        
        if (GSS_ERROR(maj_stat))
        {
            set_gss_error(maj_stat, min_stat);
            ret = AUTH_GSS_ERROR;
            goto end;
        }
        
        // Get credentials
        maj_stat = gss_acquire_cred(&min_stat, state->server_name, GSS_C_INDEFINITE,
                                    GSS_C_NO_OID_SET, GSS_C_ACCEPT, &state->server_creds, NULL, NULL);
        
        if (GSS_ERROR(maj_stat))
        {
            set_gss_error(maj_stat, min_stat);
            ret = AUTH_GSS_ERROR;
            goto end;
        }
    }
    
end:
    return ret;
}

int authenticate_gss_server_clean(gss_server_state *state)
{
    OM_uint32 min_stat;
    int ret = AUTH_GSS_COMPLETE;
    
    if (state->context != GSS_C_NO_CONTEXT)
        gss_delete_sec_context(&min_stat, &state->context, GSS_C_NO_BUFFER);
    if (state->server_name != GSS_C_NO_NAME)
        gss_release_name(&min_stat, &state->server_name);
    if (state->client_name != GSS_C_NO_NAME)
        gss_release_name(&min_stat, &state->client_name);
    if (state->server_creds != GSS_C_NO_CREDENTIAL)
        gss_release_cred(&min_stat, &state->server_creds);
    if (state->client_creds != GSS_C_NO_CREDENTIAL)
        gss_release_cred(&min_stat, &state->client_creds);
    if (state->username != NULL)
    {
        free(state->username);
        state->username = NULL;
    }
    if (state->targetname != NULL)
    {
        free(state->targetname);
        state->targetname = NULL;
    }
    if (state->response != NULL)
    {
        free(state->response);
        state->response = NULL;
    }
    
    return ret;
}

/*int authenticate_gss_server_step(gss_server_state *state, const char *challenge)
{
    OM_uint32 maj_stat;
    OM_uint32 min_stat;
    gss_buffer_desc input_token = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc output_token = GSS_C_EMPTY_BUFFER;
    int ret = AUTH_GSS_CONTINUE;
    
    // Always clear out the old response
    if (state->response != NULL)
    {
        free(state->response);
        state->response = NULL;
    }
    
    // If there is a challenge (data from the server) we need to give it to GSS
    if (challenge && *challenge)
    {
        int len;
        input_token.value = base64_decode(challenge, &len);
        input_token.length = len;
    }
    else
    {
        PyErr_SetString(KrbException_class, "No challenge parameter in request from client");
        ret = AUTH_GSS_ERROR;
        goto end;
    }
    
    maj_stat = gss_accept_sec_context(&min_stat,
                                      &state->context,
                                      state->server_creds,
                                      &input_token,
                                      GSS_C_NO_CHANNEL_BINDINGS,
                                      &state->client_name,
                                      NULL,
                                      &output_token,
                                      NULL,
                                      NULL,
                                      &state->client_creds);
    
    if (GSS_ERROR(maj_stat))
    {
        set_gss_error(maj_stat, min_stat);
        ret = AUTH_GSS_ERROR;
        goto end;
    }
    
    // Grab the server response to send back to the client
    if (output_token.length)
    {
        state->response = base64_encode((const unsigned char *)output_token.value, output_token.length);;
        maj_stat = gss_release_buffer(&min_stat, &output_token);
    }
    
    // Get the user name
    maj_stat = gss_display_name(&min_stat, state->client_name, &output_token, NULL);
    if (GSS_ERROR(maj_stat))
    {
        set_gss_error(maj_stat, min_stat);
        ret = AUTH_GSS_ERROR;
        goto end;
    }
    state->username = (char *)malloc(output_token.length + 1);
    strncpy(state->username, (char*) output_token.value, output_token.length);
    state->username[output_token.length] = 0;
    
    // Get the target name if no server creds were supplied
    if (state->server_creds == GSS_C_NO_CREDENTIAL)
    {
        gss_name_t target_name = GSS_C_NO_NAME;
        maj_stat = gss_inquire_context(&min_stat, state->context, NULL, &target_name, NULL, NULL, NULL, NULL, NULL);
        if (GSS_ERROR(maj_stat))
        {
            set_gss_error(maj_stat, min_stat);
            ret = AUTH_GSS_ERROR;
            goto end;
        }
        maj_stat = gss_display_name(&min_stat, target_name, &output_token, NULL);
        if (GSS_ERROR(maj_stat))
        {
            set_gss_error(maj_stat, min_stat);
            ret = AUTH_GSS_ERROR;
            goto end;
        }
        state->targetname = (char *)malloc(output_token.length + 1);
        strncpy(state->targetname, (char*) output_token.value, output_token.length);
        state->targetname[output_token.length] = 0;
    }

    ret = AUTH_GSS_COMPLETE;
    
end:
    if (output_token.length)
        gss_release_buffer(&min_stat, &output_token);
    if (input_token.value)
        free(input_token.value);
    return ret;
}
*/

static void set_gss_error(OM_uint32 err_maj, OM_uint32 err_min) {
  OM_uint32 maj_stat, min_stat;
  OM_uint32 msg_ctx = 0;
  gss_buffer_desc status_string;
  char buf_maj[512];
  char buf_min[512];
  
  do {
    maj_stat = gss_display_status (&min_stat,
                                   err_maj,
                                   GSS_C_GSS_CODE,
                                   GSS_C_NO_OID,
                                   &msg_ctx,
                                   &status_string);
    if(GSS_ERROR(maj_stat))
      break;
    
    strncpy(buf_maj, (char*) status_string.value, sizeof(buf_maj));
    gss_release_buffer(&min_stat, &status_string);
    
    maj_stat = gss_display_status (&min_stat,
                                   err_min,
                                   GSS_C_MECH_CODE,
                                   GSS_C_NULL_OID,
                                   &msg_ctx,
                                   &status_string);
    if (!GSS_ERROR(maj_stat)) {

      strncpy(buf_min, (char*) status_string.value , sizeof(buf_min));
      gss_release_buffer(&min_stat, &status_string);
    }
  } while (!GSS_ERROR(maj_stat) && msg_ctx != 0);
}

gss_client_response *gss_error(OM_uint32 err_maj, OM_uint32 err_min) {
  OM_uint32 maj_stat, min_stat;
  OM_uint32 msg_ctx = 0;
  gss_buffer_desc status_string;
  char *buf_maj = calloc(512, sizeof(char));
  char *buf_min = calloc(512, sizeof(char));
  char *message = NULL;
  gss_client_response *response = calloc(1, sizeof(gss_client_response));
  
  do {
    maj_stat = gss_display_status (&min_stat,
                                   err_maj,
                                   GSS_C_GSS_CODE,
                                   GSS_C_NO_OID,
                                   &msg_ctx,
                                   &status_string);
    if(GSS_ERROR(maj_stat))
      break;
    
    strncpy(buf_maj, (char*) status_string.value, 512);
    gss_release_buffer(&min_stat, &status_string);
    
    maj_stat = gss_display_status (&min_stat,
                                   err_min,
                                   GSS_C_MECH_CODE,
                                   GSS_C_NULL_OID,
                                   &msg_ctx,
                                   &status_string);
    if(!GSS_ERROR(maj_stat)) {
      strncpy(buf_min, (char*) status_string.value , 512);
      gss_release_buffer(&min_stat, &status_string);
    }
  } while (!GSS_ERROR(maj_stat) && msg_ctx != 0);

  // Join the strings
  message = calloc(1026, 1);
  // Join the two messages
  sprintf(message, "%s, %s", buf_maj, buf_min);
  // Free data
  free(buf_min);
  free(buf_maj);
  // Set the message
  response->message = message;
  // Return the message
  return response;
}
