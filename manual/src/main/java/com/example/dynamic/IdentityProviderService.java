package com.example.dynamic;

import java.util.Optional;
import java.util.Set;

/**
 * CRUD for {@link IdentityProviderConfig}
 */
public interface IdentityProviderService {

    /**
     * Reads the {@link IdentityProviderConfig} given the ID
     * @param id
     * @return
     */
    Optional<IdentityProviderConfig> readConfig(int id);


    /**
     * Lists all the configured {@link IdentityProviderConfig}s.
     * @return
     */
    Set<IdentityProviderConfig> list();
}
