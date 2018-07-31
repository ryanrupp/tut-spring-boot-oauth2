package com.example.dynamic;

import java.util.Optional;

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


}
