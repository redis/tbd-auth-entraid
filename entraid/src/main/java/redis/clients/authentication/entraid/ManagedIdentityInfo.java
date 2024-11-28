package redis.clients.authentication.entraid;

import java.util.function.Function;

import com.microsoft.aad.msal4j.ManagedIdentityId;

public class ManagedIdentityInfo {

    public enum IdentityType {
        SYSTEM_ASSIGNED, USER_ASSIGNED
    }

    public enum UserManagedIdentityType {
        CLIENT_ID(ManagedIdentityId::userAssignedClientId),
        OBJECT_ID(ManagedIdentityId::userAssignedObjectId),
        RESOURCE_ID(ManagedIdentityId::userAssignedResourceId);

        private final Function<String, ManagedIdentityId> func;

        UserManagedIdentityType(Function<String, ManagedIdentityId> func) {
            this.func = func;
        }
    }

    private IdentityType type;
    private UserManagedIdentityType userManagedIdentityType;
    private String id;

    public ManagedIdentityInfo() {
        type = IdentityType.SYSTEM_ASSIGNED;
    }

    public ManagedIdentityInfo(UserManagedIdentityType userManagedType, String id) {
        type = IdentityType.USER_ASSIGNED;
        this.userManagedIdentityType = userManagedType;
        this.id = id;
    }

    public ManagedIdentityId getId() {
        switch (type) {
        case SYSTEM_ASSIGNED:
            return ManagedIdentityId.systemAssigned();
        case USER_ASSIGNED:
            return userManagedIdentityType.func.apply(id);
        }
        // this never happens
        throw new UnsupportedOperationException(
                "Operation not supported for the given identity type");
    }
}
