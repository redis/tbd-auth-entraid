# Token-based Authentication Providers for Redis Java clients

This extension provides Token-based Authentication for Redis Java client libraries: [lettuce](https://github.com/redis/lettuce) and [Jedis](https://github.com/redis/jedis)

## Microsoft Entra ID provider

### Installation 
To install the Entra ID provider, add the following dependencies to your `pom.xml` file if you're using Maven:
```xml
<dependency>
    <groupId>redis.clients.authentication</groupId>
    <artifactId>redis-authx-entraid</artifactId>
    <version>0.1.1-beta1</version>
</dependency>
```
If you're using Gradle, add the following dependencies to your `build.gradle` file:

```
implementation 'redis.clients.authentication:redis-authx-entraid:0.1.1-beta1'
```

### Quick Start
Basic usage would look like this:
```java
    TokenAuthConfig tokenAuthConfig = EntraIDTokenAuthConfigBuilder.builder()
        .clientId("YOUR_CLIENT_ID").secret("YOUR_SECRET")
        .authority("YOUR_AUTHORITY").scopes("SCOPES").build();
```
With the `tokenAuthConfig` provided, both Jedis and Lettuce clients can automatically handle Reauthentication with EntraID.

Refer to the [test files](https://github.com/redis/tbd-auth-entraid/tree/main/entraid/src/test/java/redis/clients/authentication) for more examples and detailed usage.
