package org.example;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.LambdaLogger;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public class CustomAuthorizer implements RequestHandler<APIGatewayProxyRequestEvent, Map<String, Object>> {

    private static final String COGNITO_TOKEN_URL = "https://your-cognito-domain/oauth2/token";
    private static final String CLIENT_ID = "your-client-id";
    private static final String CLIENT_SECRET = "your-client-secret";

    @Override
    public Map<String, Object> handleRequest(APIGatewayProxyRequestEvent event, Context context) {
        LambdaLogger lambdaLogger = context.getLogger();
        lambdaLogger.log("Body = " + event.getBody());
        event.getHeaders().entrySet()
                                 .forEach(e-> lambdaLogger.log("key = "+ e.getKey() + " , value = " + e.getValue()+ "\n") );
        Map<String, String> headers = event.getHeaders();
        String resource = headers.get("methodArn");
        Map<String, String> ctx = new HashMap<>();

        APIGatewayProxyRequestEvent.ProxyRequestContext proxyContext = event.getRequestContext();
        String arn = String.format("arn:aws:execute-api:%s:%s:%s/%s/%s/%s",
                                   System.getenv("AWS_REGION"),
                                   proxyContext.getAccountId(),
                                   proxyContext.getApiId(),
                                   proxyContext.getStage(),
                                   proxyContext.getHttpMethod(),
                                   "*");
        lambdaLogger.log("Arn..." + arn);
        //String effect = "Allow";
        String effect = "Deny";
        try {
            //JwtUtil.validateToken(token);
            lambdaLogger.log("Success, effect..." + effect);
            ctx.put("message", "Success");
        } catch (Exception e) {
            effect = "Deny";
            ctx.put("message", e.getMessage());
            lambdaLogger.log("Deny, Exception..." + e.getMessage());
        }
        lambdaLogger.log("principalId = user, effect = " + effect + " , resource = " + arn);

        Map<String, Object> stringObjectMap = generatePolicy("user", effect, arn);
        lambdaLogger.log("auth response = " + stringObjectMap );
        return stringObjectMap;
    }

    private String getAccessToken() {
        CloseableHttpClient httpClient = HttpClients.createDefault();
        HttpPost post = new HttpPost(COGNITO_TOKEN_URL);

        post.setHeader("Content-Type", "application/x-www-form-urlencoded");
        post.setHeader("Authorization", "Basic " + encodeBase64(CLIENT_ID + ":" + CLIENT_SECRET));

        try {
            StringEntity entity = new StringEntity("grant_type=client_credentials");
            post.setEntity(entity);

            CloseableHttpResponse response = httpClient.execute(post);
            String responseBody = EntityUtils.toString(response.getEntity());

            ObjectMapper mapper = new ObjectMapper();
            JsonNode jsonNode = mapper.readTree(responseBody);

            return jsonNode.get("access_token").asText();
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }

    private String encodeBase64(String value) {
        return java.util.Base64.getEncoder().encodeToString(value.getBytes());
    }

    private Map<String, Object> generatePolicy(String principalId, String effect, String resource) {
        Map<String, Object> authResponse = new HashMap<>();
        authResponse.put("principalId", principalId);
        Map<String, Object> policyDocument = new HashMap<>();
        policyDocument.put("Version", "2012-10-17"); // default version
        Map<String, String> statementOne = new HashMap<>();
        statementOne.put("Action", "execute-api:Invoke"); // default action
        statementOne.put("Effect", effect);
        statementOne.put("Resource", resource);
        policyDocument.put("Statement", new Object[] {statementOne});
        authResponse.put("policyDocument", policyDocument);
        if ("Allow".equals(effect)) {
            Map<String, Object> context = new HashMap<>();
            context.put("key", "value");
            context.put("numKey", Long.valueOf(1L));
            context.put("boolKey", Boolean.TRUE);
            authResponse.put("context", context);
        }
        return authResponse;
    }
}