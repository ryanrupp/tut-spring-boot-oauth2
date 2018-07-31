package com.example.dynamic;

import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * {@link IdentityProviderService} that reads configurations directly from in memory objects.
 * In a real world application replace this with a service implementation that reads the configuration
 * from the database.
 */
class InMemoryIdentityProviderService implements IdentityProviderService {

    private final ConcurrentMap<Integer, IdentityProviderConfig> identityConfigs = new ConcurrentHashMap<>();

    InMemoryIdentityProviderService(Set<IdentityProviderConfig> configs) {
        for (IdentityProviderConfig config : configs) {
            identityConfigs.put(config.id, config);
        }
    }

    @Override
    public Optional<IdentityProviderConfig> readConfig(int id) {
        return Optional.ofNullable(identityConfigs.get(id));
    }
}
