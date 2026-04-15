package com.e2ew.e2e.keys.security;

import java.util.Optional;

import com.e2ew.e2e.keys.model.AcceptEncryptionMethod;
import com.e2ew.e2e.keys.model.ClientKeys;

/**
 * Servicio para la gestión de llaves de cliente
 */
public interface ClientKeysSession {
    /**
     * Obtiene las llaves de un cliente por su ID
     *
     * @param clientId ID del cliente
     * @return Llaves del cliente si existen objeto Optional vacío en caso contrario
     */
    Optional<ClientKeys> getClientKeys(String clientId);

    /**
     * Cierra la sesión de un cliente por su ID
     *
     * @NoteApi Esta operación elimina las llaves del cliente de la sesión activa y cierra su sesión.
     * Esto permite eliminar sesiones no autorizadas o manipuladas por un atacante.
     * @param clientId ID del cliente
     */
    void closeSessionClient(String clientId);

    /**
     * Obtiene el método de encriptación permitido para un cliente
     * @param clientId ID del cliente
     * @return Método de encriptación permitido
     */
    AcceptEncryptionMethod getAlgEncPermission(String clientId);
}
