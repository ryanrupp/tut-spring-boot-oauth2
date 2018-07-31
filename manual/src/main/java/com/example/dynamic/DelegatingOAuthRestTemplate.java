package com.example.dynamic;

import org.springframework.boot.autoconfigure.security.oauth2.resource.UserInfoTokenServices;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestOperations;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.resource.UserRedirectRequiredException;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.web.client.RequestCallback;
import org.springframework.web.client.ResponseExtractor;
import org.springframework.web.client.RestClientException;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.servlet.http.HttpServletRequest;
import java.net.URI;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * A {@link OAuth2RestOperations} and {@link ResourceServerTokenServices} implementation that
 * delegates to the correct underlying implementations based on the {@link IdentityProviderConfig}
 * which is determined by the request URI e.g. /login/oauth/<identity_provider_id>
 *
 * This allows for dynamic selection of the OAuth provider and also runtime swapping of the configuration.
 */
class DelegatingOAuthRestTemplate implements OAuth2RestOperations, ResourceServerTokenServices {

    private final OAuth2ClientContext oauth2ClientContext;
    private final IdentityProviderService identityProviderService;
    private final ConcurrentMap<Integer, RestOperationsConfig> delegates = new ConcurrentHashMap<>();

    DelegatingOAuthRestTemplate(OAuth2ClientContext oauth2ClientContext, IdentityProviderService identityProviderService) {
        this.oauth2ClientContext = oauth2ClientContext;
        this.identityProviderService = identityProviderService;
    }

    // Config holder class
    private static class RestOperationsConfig {
        private final OAuth2RestOperations restOperations;
        private final IdentityProviderConfig config;

        private RestOperationsConfig(OAuth2RestOperations restOperations, IdentityProviderConfig config) {
            this.restOperations = restOperations;
            this.config = config;
        }
    }

    private RestOperationsConfig delegateConfig() {
        // Figure out the correct delegateRest somehow e.g. the URL or request attribute
        // In this example we're using the URL
        HttpServletRequest curRequest =
                ((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes())
                        .getRequest();

        // In this example we grab the identity provider ID from the end of the URL e.g.
        // /login/oauth/<id>
        String requestURI = curRequest.getRequestURI();
        String providerIdAsString = requestURI.substring(requestURI.lastIndexOf("/") + 1);
        int providerId = Integer.parseInt(providerIdAsString);

        IdentityProviderConfig currentConfig = identityProviderService.readConfig(providerId).orElseThrow(() -> new IllegalArgumentException("Invalid identity provider"));

        // Get existing or build here
        RestOperationsConfig restOpsConfig = delegates.computeIfAbsent(currentConfig.id, (key) -> buildRestTemplate(currentConfig));

        // Check also if the config has changed in the DB in which case we rebuild the OAuth client
        // Note when using JPA objects the hash will be the ID so this compare may be different or rather you're storing
        // a "snapshot" of the configuration. See how external databases are managed which is the same idea.
        if (!restOpsConfig.config.equals(currentConfig)) {
            System.out.println("The OAuth configuration has changed so rebuilding for identity provider: " + currentConfig.id);
            // TODO make this thread safe although not a big deal to build twice here
            // also may need to close the underlying http connection pool (depending on how it's configured)
            delegates.put(currentConfig.id, buildRestTemplate(currentConfig));
        }

        return restOpsConfig;
    }

    private ResourceServerTokenServices delegateTokenServices() {
        RestOperationsConfig restConfig = delegateConfig();
        // UserInfoTokenServices looks like it's cheap to build (expensive object is the rest operations because it uses a thread pool)
        // Just building this everytime here although it could be stored as well in memory
        UserInfoTokenServices userInfoTokenServices = new UserInfoTokenServices(restConfig.config.resourceServerProperties.getUserInfoUri(),
                restConfig.config.codeResourceDetails.getClientId());
        userInfoTokenServices.setRestTemplate(restConfig.restOperations);
        return userInfoTokenServices;
    }

    private OAuth2RestOperations delegateRest() {
        return delegateConfig().restOperations;
    }

    private RestOperationsConfig buildRestTemplate(IdentityProviderConfig identityProviderConfig) {
        System.out.println("Building rest client for identity provider: " + identityProviderConfig.id);
        OAuth2RestTemplate restTemplate = new OAuth2RestTemplate(identityProviderConfig.codeResourceDetails, oauth2ClientContext);
        return new RestOperationsConfig(restTemplate, identityProviderConfig);
    }

    // Below are all delegate operations that find the correct implementation and delegate to it

    @Override
    public OAuth2Authentication loadAuthentication(String accessToken) throws AuthenticationException, InvalidTokenException {
        return delegateTokenServices().loadAuthentication(accessToken);
    }

    @Override
    public OAuth2AccessToken readAccessToken(String accessToken) {
        return delegateTokenServices().readAccessToken(accessToken);
    }

    @Override
    public OAuth2AccessToken getAccessToken() throws UserRedirectRequiredException {
        return delegateRest().getAccessToken();
    }

    @Override
    public OAuth2ClientContext getOAuth2ClientContext() {
        return delegateRest().getOAuth2ClientContext();
    }

    @Override
    public OAuth2ProtectedResourceDetails getResource() {
        return delegateRest().getResource();
    }

    @Override
    public <T> T getForObject(String s, Class<T> aClass, Object... objects) throws RestClientException {
        return delegateRest().getForObject(s, aClass, objects);
    }

    @Override
    public <T> T getForObject(String s, Class<T> aClass, Map<String, ?> map) throws RestClientException {
        return delegateRest().getForObject(s, aClass, map);
    }

    @Override
    public <T> T getForObject(URI uri, Class<T> aClass) throws RestClientException {
        return delegateRest().getForObject(uri, aClass);
    }

    @Override
    public <T> ResponseEntity<T> getForEntity(String s, Class<T> aClass, Object... objects) throws RestClientException {
        return delegateRest().getForEntity(s, aClass, objects);
    }

    @Override
    public <T> ResponseEntity<T> getForEntity(String s, Class<T> aClass, Map<String, ?> map) throws RestClientException {
        return delegateRest().getForEntity(s, aClass, map);
    }

    @Override
    public <T> ResponseEntity<T> getForEntity(URI uri, Class<T> aClass) throws RestClientException {
        return delegateRest().getForEntity(uri, aClass);
    }

    @Override
    public HttpHeaders headForHeaders(String s, Object... objects) throws RestClientException {
        return delegateRest().headForHeaders(s, objects);
    }

    @Override
    public HttpHeaders headForHeaders(String s, Map<String, ?> map) throws RestClientException {
        return delegateRest().headForHeaders(s, map);
    }

    @Override
    public HttpHeaders headForHeaders(URI uri) throws RestClientException {
        return delegateRest().headForHeaders(uri);
    }

    @Override
    public URI postForLocation(String s, Object o, Object... objects) throws RestClientException {
        return delegateRest().postForLocation(s, o, objects);
    }

    @Override
    public URI postForLocation(String s, Object o, Map<String, ?> map) throws RestClientException {
        return delegateRest().postForLocation(s, o, map);
    }

    @Override
    public URI postForLocation(URI uri, Object o) throws RestClientException {
        return delegateRest().postForLocation(uri, o);
    }

    @Override
    public <T> T postForObject(String s, Object o, Class<T> aClass, Object... objects) throws RestClientException {
        return delegateRest().postForObject(s, o, aClass, objects);
    }

    @Override
    public <T> T postForObject(String s, Object o, Class<T> aClass, Map<String, ?> map) throws RestClientException {
        return delegateRest().postForObject(s, o, aClass, map);
    }

    @Override
    public <T> T postForObject(URI uri, Object o, Class<T> aClass) throws RestClientException {
        return delegateRest().postForObject(uri, o, aClass);
    }

    @Override
    public <T> ResponseEntity<T> postForEntity(String s, Object o, Class<T> aClass, Object... objects) throws RestClientException {
        return delegateRest().postForEntity(s, o, aClass, objects);
    }

    @Override
    public <T> ResponseEntity<T> postForEntity(String s, Object o, Class<T> aClass, Map<String, ?> map) throws RestClientException {
        return delegateRest().postForEntity(s, o, aClass, map);
    }

    @Override
    public <T> ResponseEntity<T> postForEntity(URI uri, Object o, Class<T> aClass) throws RestClientException {
        return delegateRest().postForEntity(uri, o, aClass);
    }

    @Override
    public void put(String s, Object o, Object... objects) throws RestClientException {
        delegateRest().put(s, o, objects);
    }

    @Override
    public void put(String s, Object o, Map<String, ?> map) throws RestClientException {
        delegateRest().put(s, o, map);
    }

    @Override
    public void put(URI uri, Object o) throws RestClientException {
        delegateRest().put(uri, o);
    }

    @Override
    public <T> T patchForObject(String s, Object o, Class<T> aClass, Object... objects) throws RestClientException {
        return delegateRest().patchForObject(s, o, aClass, objects);
    }

    @Override
    public <T> T patchForObject(String s, Object o, Class<T> aClass, Map<String, ?> map) throws RestClientException {
        return delegateRest().patchForObject(s, o, aClass, map);
    }

    @Override
    public <T> T patchForObject(URI uri, Object o, Class<T> aClass) throws RestClientException {
        return delegateRest().patchForObject(uri, o, aClass);
    }

    @Override
    public void delete(String s, Object... objects) throws RestClientException {
        delegateRest().delete(s, objects);
    }

    @Override
    public void delete(String s, Map<String, ?> map) throws RestClientException {
        delegateRest().delete(s, map);
    }

    @Override
    public void delete(URI uri) throws RestClientException {
        delegateRest().delete(uri);
    }

    @Override
    public Set<HttpMethod> optionsForAllow(String s, Object... objects) throws RestClientException {
        return delegateRest().optionsForAllow(s, objects);
    }

    @Override
    public Set<HttpMethod> optionsForAllow(String s, Map<String, ?> map) throws RestClientException {
        return delegateRest().optionsForAllow(s, map);
    }

    @Override
    public Set<HttpMethod> optionsForAllow(URI uri) throws RestClientException {
        return delegateRest().optionsForAllow(uri);
    }

    @Override
    public <T> ResponseEntity<T> exchange(String s, HttpMethod httpMethod, HttpEntity<?> httpEntity, Class<T> aClass, Object... objects) throws RestClientException {
        return delegateRest().exchange(s, httpMethod, httpEntity, aClass, objects);
    }

    @Override
    public <T> ResponseEntity<T> exchange(String s, HttpMethod httpMethod, HttpEntity<?> httpEntity, Class<T> aClass, Map<String, ?> map) throws RestClientException {
        return delegateRest().exchange(s, httpMethod, httpEntity, aClass,map);
    }

    @Override
    public <T> ResponseEntity<T> exchange(URI uri, HttpMethod httpMethod, HttpEntity<?> httpEntity, Class<T> aClass) throws RestClientException {
        return delegateRest().exchange(uri, httpMethod, httpEntity, aClass);
    }

    @Override
    public <T> ResponseEntity<T> exchange(String s, HttpMethod httpMethod, HttpEntity<?> httpEntity, ParameterizedTypeReference<T> parameterizedTypeReference, Object... objects) throws RestClientException {
        return delegateRest().exchange(s, httpMethod, httpEntity, parameterizedTypeReference, objects);
    }

    @Override
    public <T> ResponseEntity<T> exchange(String s, HttpMethod httpMethod, HttpEntity<?> httpEntity, ParameterizedTypeReference<T> parameterizedTypeReference, Map<String, ?> map) throws RestClientException {
        return delegateRest().exchange(s, httpMethod, httpEntity, parameterizedTypeReference, map);
    }

    @Override
    public <T> ResponseEntity<T> exchange(URI uri, HttpMethod httpMethod, HttpEntity<?> httpEntity, ParameterizedTypeReference<T> parameterizedTypeReference) throws RestClientException {
        return delegateRest().exchange(uri, httpMethod, httpEntity, parameterizedTypeReference);
    }

    @Override
    public <T> ResponseEntity<T> exchange(RequestEntity<?> requestEntity, Class<T> aClass) throws RestClientException {
        return delegateRest().exchange(requestEntity, aClass);
    }

    @Override
    public <T> ResponseEntity<T> exchange(RequestEntity<?> requestEntity, ParameterizedTypeReference<T> parameterizedTypeReference) throws RestClientException {
        return delegateRest().exchange(requestEntity, parameterizedTypeReference);
    }

    @Override
    public <T> T execute(String s, HttpMethod httpMethod, RequestCallback requestCallback, ResponseExtractor<T> responseExtractor, Object... objects) throws RestClientException {
        return delegateRest().execute(s, httpMethod, requestCallback, responseExtractor, objects);
    }

    @Override
    public <T> T execute(String s, HttpMethod httpMethod, RequestCallback requestCallback, ResponseExtractor<T> responseExtractor, Map<String, ?> map) throws RestClientException {
        return delegateRest().execute(s, httpMethod, requestCallback, responseExtractor, map);
    }

    @Override
    public <T> T execute(URI uri, HttpMethod httpMethod, RequestCallback requestCallback, ResponseExtractor<T> responseExtractor) throws RestClientException {
        return delegateRest().execute(uri, httpMethod, requestCallback, responseExtractor);
    }
}
