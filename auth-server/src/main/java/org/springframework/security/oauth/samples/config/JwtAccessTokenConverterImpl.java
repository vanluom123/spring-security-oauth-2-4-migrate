package org.springframework.security.oauth.samples.config;

import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.jwt.crypto.sign.SignatureVerifier;
import org.springframework.security.jwt.crypto.sign.Signer;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.util.JsonParser;
import org.springframework.security.oauth2.common.util.JsonParserFactory;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;

import java.util.HashMap;
import java.util.Map;

@SuppressWarnings("deprecation")
public class JwtAccessTokenConverterImpl extends JwtAccessTokenConverter {
  private final JsonParser objectMapper;
  private final Signer signer;

  public JwtAccessTokenConverterImpl(Signer signer, SignatureVerifier verifier) {
    objectMapper = JsonParserFactory.create();
    this.signer = signer;
    this.setSigner(signer);
    this.setVerifier(verifier);
  }

  @Override
  protected String encode(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {
    String content;
    try {
      content = this.objectMapper.formatMap(getAccessTokenConverter().convertAccessToken(accessToken, authentication));
    }
    catch (Exception ex) {
      throw new IllegalStateException("Cannot convert access token to JSON", ex);
    }
    Map<String, String> headers = new HashMap<>();
    headers.put("kid", KeyConfig.VERIFIER_KEY_ID);
    return JwtHelper.encode(content, signer, headers).getEncoded();
  }
}
