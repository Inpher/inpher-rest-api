package rest.service;

import org.apache.commons.io.FileUtils;
import org.glassfish.jersey.media.multipart.FormDataContentDisposition;
import org.glassfish.jersey.media.multipart.FormDataParam;
import org.inpher.clientapi.*;
import org.inpher.clientapi.crypto.Certificate;
import org.inpher.clientapi.efs.BackendIterator;
import org.inpher.clientapi.efs.Element;
import org.inpher.clientapi.efs.SearchableFileSystem;
import org.inpher.clientapi.efs.exceptions.ParentNotFoundException;
import org.inpher.clientapi.efs.exceptions.PathAlreadyExistsException;
import org.inpher.clientapi.efs.exceptions.PathIsDirectoryException;
import org.inpher.clientapi.efs.exceptions.PathNotFoundException;
import org.inpher.clientapi.exceptions.*;

import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.ResponseBuilder;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;


@Path("/")
public class UltraService {
    private static InpherClient inpherClient;
    private static Map<String, SearchableFileSystem> sfss;
    //private static String AUTH_TOKEN = "auth_token";

    static {
        //Security.addProvider(new BouncyCastleProvider());
        sfss = new ConcurrentHashMap<>();
        try {
            //inpherClient = InpherClient.getClient();
            URL config = UltraService.class.getResource("/config.properties");
            if (config != null) {
                System.err.println("Using " + config.getFile());
                inpherClient = InpherClient.getClient(config.getFile());
            } else {
                System.err.println("No config properties found");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @GET
    @Produces(MediaType.TEXT_HTML)
    public String sayHtmlHello() {
        return "Hello from _ultra rest API";
    }

    @Path("testJSON")
    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response sayJsonHello(User user) {
        HashMap<String, Object> reps = new HashMap<>();
        reps.put("user", user);
        reps.put("message", "Hello from _ultra rest API");
        return Response.ok(reps).build();
    }

    @Path("register")
    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    public Response register(User user) {
        if (user.getName() == null || user.getPassword() == null) {
            return Response.status(400).entity("password and name should not be empty").build();
        }
        try {
            inpherClient.registerUser(new InpherUser(user.getName(), user.getPassword()));
        } catch (ExistingUserException e) {
            return Response.status(409).entity("user already exists").build();
        }
        return Response.ok().build();
    }

    @Path("register")
    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public Response register(@FormParam("username") String username,
            @FormParam("password") String password) {
        if (username == null || password == null) {
            return Response.status(400).entity("password and name should not be empty").build();
        }
        try {
            inpherClient.registerUser(new InpherUser(username, password));
        } catch (ExistingUserException e) {
            return Response.status(409).entity("user already exists").build();
        }
        return Response.ok().build();
    }

    private Response privLogin(String username, String password) {
        SearchableFileSystem sfs;
        try {
            sfs = inpherClient.loginUser(new InpherUser(username, password));
        } catch (AuthenticationException e) {
            return Response.status(409).entity("Authentication failed").build();
        }

        //String result = "Person logged in successfully : " + username;
        String token = UUID.randomUUID().toString();
        //NewCookie authToken = new NewCookie(AUTH_TOKEN, token);
        sfss.put(token, sfs);
        HashMap<String, Object> reps = new HashMap<>();
        reps.put("auth_token", token);
        reps.put("username", username);
        return Response.status(201).entity(reps).build();
    }

    @Path("login")
    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.APPLICATION_JSON)
    public Response login(@FormParam("username") String username,
            @FormParam("password") String password) {
        return privLogin(username, password);
    }

    @Path("login")
    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response login(User user) {
        return privLogin(user.getName(), user.getPassword());
    }

    @Path("logout")
    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public Response logout(@HeaderParam("auth_token") String authToken) {
        if (authToken == null) {
            return Response.status(409).entity("Authentication failed").build();
        }
        SearchableFileSystem sfs = sfss.get(authToken);
        if (sfs == null) {
            return Response.status(409).entity("Authentication failed").build();
        }
        inpherClient.logoutUser(sfs);
        return Response.status(201).entity("logged out").build();
    }

    @Path("shutdown")
    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public Response shutdown() {
        //        inpherClient.close();
        inpherClient = null;
        return Response.status(201).entity("closed").build();
    }

    @Path("userCertificate")
    @GET
    @Produces(MediaType.TEXT_PLAIN)
    public Response userCertificate(@QueryParam("username") String username,
            @HeaderParam("auth_token") String authToken) {
        if (authToken == null) {
            return Response.status(409).entity("Authentication failed").build();
        }
        SearchableFileSystem sfs = sfss.get(authToken);
        if (sfs == null) {
            return Response.status(409).entity("Authentication failed").build();
        }
        Certificate cert = inpherClient.getUserCertificate(username);
        return Response.status(201).entity(cert.toString()).build();
    }

    // @Path("submitGroupCertificate")
    // @POST
    // public Response submitGroupCertificate(@FormParam("cert") String
    // certificate,
    // @FormParam("groupName") String groupName, @CookieParam("auth_token")
    // Cookie authToken) {
    // if (authToken == null) {
    // return Response.status(409).entity("Authentication failed").build();
    // }
    // SearchableFileSystem sfs = sfss.get(authToken);
    // if (sfs == null) {
    // return Response.status(409).entity("Authentication failed").build();
    // }
    // inpherClient.submitGroupCertificate(new Certificate(cert), groupName);
    // return Response.status(201).entity("certificate submitted").build();
    // }

    @Path("doesSharingGroupExists")
    @GET
    public Response doesSharingGroupExists(@QueryParam("groupName") String groupName,
            @HeaderParam("auth_token") String authToken) {
        if (authToken == null) {
            return Response.status(409).entity("Authentication failed").build();
        }
        SearchableFileSystem sfs = sfss.get(authToken);
        if (sfs == null) {
            return Response.status(409).entity("Authentication failed").build();
        }
        Boolean exists = inpherClient.doesSharingGroupExists(groupName);
        return Response.status(201).entity(exists.toString()).build();
    }

    @Path("createSharingGroup")
    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    public Response createSharingGroup(GroupRequest groupRequest,
            @HeaderParam("auth_token") String authToken) {
        if (authToken == null) {
            return Response.status(409).entity("Authentication failed").build();
        }
        SearchableFileSystem sfs = sfss.get(authToken);
        if (sfs == null) {
            return Response.status(409).entity("Authentication failed").build();
        }
        inpherClient
                .createSharingGroup(sfs, groupRequest.getGroupName(), groupRequest.getUsernames());
        return Response.status(201).entity("logged out").build();
    }

    @Path("mkdir")
    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public Response mkdir(@FormParam("dir") String dir,
            @HeaderParam("auth_token") String authToken) {
        if (authToken == null) {
            return Response.status(409).entity("Authentication failed").build();
        }
        SearchableFileSystem sfs = sfss.get(authToken);
        if (sfs == null) {
            return Response.status(409).entity("Authentication failed").build();
        }
        try {
            sfs.mkdir(FrontendPath.parse(dir));
        } catch (ParentNotFoundException e) {
            return Response.status(400).entity("The parent of the dir does not exist.").build();
        } catch (InpherRuntimeException e) {
            return Response.status(400).entity("An error occured. Please check: " + e.getMessage())
                    .build();
        }

        String result = "Dir created successfully : " + dir;
        return Response.status(201).entity(result).build();
    }

    @Path("listDir")
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response listDir(@QueryParam("dir") String dir,
            @HeaderParam("auth_token") String authToken) {
        if (authToken == null) {
            return Response.status(409).entity("Authentication failed").build();
        }
        SearchableFileSystem sfs = sfss.get(authToken);
        if (sfs == null) {
            return Response.status(409).entity("Authentication failed").build();
        }
        ArrayList<Map<String, String>> arr = new ArrayList<>();
        try {
            BackendIterator<Element> iterator = sfs.list(FrontendPath.parse(dir));
            while (iterator.hasNext()) {
                Element el = iterator.next();
                Map<String, String> elJS = elementToJSObject(el);
                arr.add(elementToJSObject(el));
            }
        } catch (InpherRuntimeException e) {
            return Response.status(400).entity("An error occured. Please check: " + e.getMessage())
                    .build();
        } catch (PathNotFoundException e) {
            return Response.status(400).entity("The dir does not exist.").build();
        }
        HashMap<String, Object> ret = new HashMap<>();
        ret.put("list", arr);
        return Response.ok(ret).build();
    }

    private Map<String, String> elementToJSObject(Element el) {
        Map<String, String> elMap = new HashMap<>();
        elMap.put("path", el.getFrontendURI());
        elMap.put("type", el.getType().name());
        elMap.put("size", "" + el.getSize());
        return elMap;
    }

    @Path("upload")
    @POST
    @Consumes(MediaType.MULTIPART_FORM_DATA)
    public Response uploadFile(@FormDataParam("content") final InputStream content,
            @FormDataParam("content") FormDataContentDisposition contentDispositionHeader,
            @FormDataParam("name") String name, @HeaderParam("auth_token") String authToken) {
        if (authToken == null) {
            return Response.status(409).entity("Authentication failed").build();
        }
        SearchableFileSystem sfs = sfss.get(authToken);

        if (sfs == null) {
            return Response.status(409).entity("Authentication failed").build();
        }
        File file = new File("temp.tmp");
        try {
            FileUtils.copyInputStreamToFile(content, file);
        } catch (IOException e) {
            return Response.status(400).entity("An error occured. Please check: " + e.getMessage())
                    .build();
        }
        try {
            sfs.upload(file, FrontendPath.parse(name));
        } catch (ParentNotFoundException e) {
            return Response.status(400).entity("The parent of the dir does not exists.").build();
        } catch (InpherRuntimeException e) {
            return Response.status(400).entity("An error occured. Please check: " + e.getMessage())
                    .build();
        }
        return Response.ok("file uploaded").build();
    }

    @Path("download")
    @GET
    @Produces("text/plain")
    public Response downloadFile(@QueryParam("fileName") String fileName,
            @HeaderParam("auth_token") String authToken) {
        if (authToken == null) {
            return Response.status(409).entity("Authentication failed").build();
        }
        SearchableFileSystem sfs = sfss.get(authToken);

        if (sfs == null) {
            return Response.status(409).entity("Authentication failed").build();
        }
        File file = new File("temp.tmp");
        FrontendPath filePath = FrontendPath.parse(fileName);
        try {
            sfs.download(filePath, file);
        } catch (PathNotFoundException e) {
            return Response.status(400).entity("The file does not exist.").build();
        } catch (PathIsDirectoryException e) {
            return Response.status(400).entity("The path points to a directory").build();
        } catch (InpherRuntimeException e) {
            return Response.status(400).entity("An error occured. Please check: " + e.getMessage())
                    .build();
        }
        ResponseBuilder response = Response.ok((Object) file);
        response.header("Content-Disposition",
                "attachment; filename=\"" + filePath.getLastElementName() + "\"");
        return response.build();
    }

    @Path("delete")
    @DELETE
    public Response delete(@QueryParam("path") String path,
            @QueryParam("recursive") boolean recursive,
            @HeaderParam("auth_token") String authToken) {
        if (authToken == null) {
            return Response.status(409).entity("Authentication failed").build();
        }
        SearchableFileSystem sfs = sfss.get(authToken);

        if (sfs == null) {
            return Response.status(409).entity("Authentication failed").build();
        }
        try {
            sfs.delete(FrontendPath.parse(path), recursive);
        } catch (NonEmptyDirectoryException e) {
            return Response.status(400).entity("The path points to a directory that is not emptry")
                    .build();
        } catch (PathNotOwnedByUserException e) {
            return Response.status(400)
                    .entity("You cannot delete the resource. The path does not belong to you")
                    .build();
        } catch (PathNotFoundException e) {
            return Response.status(400).entity("The resource does not exist.").build();
        } catch (InpherRuntimeException e) {
            return Response.status(400).entity("An error occured. Please check: " + e.getMessage())
                    .build();
        }
        return Response.ok("resource deleted").build();
    }

    @Path("move")
    @GET
    public Response move(@QueryParam("oldPath") String oldPath,
            @QueryParam("newPath") String newPath, @HeaderParam("auth_token") String authToken) {
        if (authToken == null) {
            return Response.status(409).entity("Authentication failed").build();
        }
        SearchableFileSystem sfs = sfss.get(authToken);

        if (sfs == null) {
            return Response.status(409).entity("Authentication failed").build();
        }
        try {
            sfs.move(FrontendPath.parse(oldPath), FrontendPath.parse(newPath));
        } catch (PathNotFoundException e) {
            return Response.status(400).entity("The resource does not exist.").build();
        } catch (PathAlreadyExistsException e) {
            return Response.status(400).entity("The new path is already in use.").build();
        } catch (InpherRuntimeException e) {
            return Response.status(400).entity("An error occured. Please check: " + e.getMessage())
                    .build();
        }
        return Response.ok("resource moved").build();
    }

    @Path("search")
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response search(@QueryParam("keywords") String keywords,
            @HeaderParam("auth_token") String authToken) {
        if (authToken == null) {
            return Response.status(409).entity("Authentication failed").build();
        }
        SearchableFileSystem sfs = sfss.get(authToken);

        if (sfs == null) {
            return Response.status(409).entity("Authentication failed").build();
        }
        String[] words = keywords.split(" ");
        SearchResponse results = sfs.search(Arrays.asList(words));
        ArrayList<HashMap<String, Object>> arr = new ArrayList<>();
        for (RankedSearchResult el : results.getAllRankedSearchResults()) {
            HashMap<String, Object> rankedResult = new HashMap<>();
            rankedResult.put("score", el.getScore());
            rankedResult.put("path", el.getPath().toString());
            arr.add(rankedResult);
        }

        HashMap<String, Object> ret = new HashMap<>();
        ret.put("totalHits", results.getTotalHits());
        ret.put("results", arr);
        return Response.ok(ret).build();
    }

    @Path("searchPaged")
    @GET
    public Response search(@QueryParam("keywords") String keywords, @QueryParam("page") int page,
            @QueryParam("numRes") int numRes, @HeaderParam("auth_token") String authToken) {
        if (authToken == null) {
            return Response.status(409).entity("Authentication failed").build();
        }
        SearchableFileSystem sfs = sfss.get(authToken);

        if (sfs == null) {
            return Response.status(409).entity("Authentication failed").build();
        }
        String[] words = keywords.split(" ");
        SearchResponse results = sfs.search(Arrays.asList(words), page, numRes);
        ArrayList<RankedSearchResult> arr = new ArrayList<>();
        for (RankedSearchResult el : results.getAllRankedSearchResults()) {
            arr.add(el);
        }

        HashMap<String, Object> ret = new HashMap<>();
        ret.put("totalHits", results.getTotalHits());
        ret.put("results", arr);
        return Response.ok(ret.toString()).build();
    }

    @Path("isFile")
    @GET
    public Response isFile(@QueryParam("path") String path,
            @HeaderParam("auth_token") String authToken) {
        if (authToken == null) {
            return Response.status(409).entity("Authentication failed").build();
        }
        SearchableFileSystem sfs = sfss.get(authToken);

        if (sfs == null) {
            return Response.status(409).entity("Authentication failed").build();
        }
        Boolean isFile = sfs.isFile(FrontendPath.parse(path));
        return Response.ok(isFile.toString()).build();
    }

    @Path("isDirectory")
    @GET
    public Response isDirectory(@QueryParam("path") String path,
            @HeaderParam("auth_token") String authToken) {
        if (authToken == null) {
            return Response.status(409).entity("Authentication failed").build();
        }
        SearchableFileSystem sfs = sfss.get(authToken);

        if (sfs == null) {
            return Response.status(409).entity("Authentication failed").build();
        }
        Boolean isDirectory = sfs.isDirectory(FrontendPath.parse(path));
        return Response.ok(isDirectory.toString()).build();
    }

    @Path("exists")
    @GET
    public Response exists(@QueryParam("path") String path,
            @HeaderParam("auth_token") String authToken) {
        if (authToken == null) {
            return Response.status(409).entity("Authentication failed").build();
        }
        SearchableFileSystem sfs = sfss.get(authToken);

        if (sfs == null) {
            return Response.status(409).entity("Authentication failed").build();
        }
        Boolean exists = sfs.exists(FrontendPath.parse(path));
        return Response.ok(exists.toString()).build();
    }

    @Path("listGroups")
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response listGroups(@HeaderParam("auth_token") String authToken) {
        if (authToken == null) {
            return Response.status(409).entity("Authentication failed").build();
        }
        SearchableFileSystem sfs = sfss.get(authToken);

        if (sfs == null) {
            return Response.status(409).entity("Authentication failed").build();
        }
        Collection<String> groups = sfs.listGroups();
        ArrayList<String> arr = new ArrayList<>();
        for (String group : groups) {
            arr.add(group);
        }
        return Response.ok(arr).build();
    }

    @Path("listAuthorizedGroups")
    @GET
    public Response listAuthorizedGroups(@QueryParam("path") String path,
            @HeaderParam("auth_token") String authToken) {
        if (authToken == null) {
            return Response.status(409).entity("Authentication failed").build();
        }
        SearchableFileSystem sfs = sfss.get(authToken);

        if (sfs == null) {
            return Response.status(409).entity("Authentication failed").build();
        }
        Collection<String> groups = null;
        try {
            groups = sfs.getAuthorizedGroups(FrontendPath.parse(path));
        } catch (PathNotFoundException e) {
            return Response.status(400).entity("The resource does not exist.").build();
        } catch (InpherRuntimeException e) {
            return Response.status(400).entity("An error occured. Please check: " + e.getMessage())
                    .build();
        }
        ArrayList<String> arr = new ArrayList<>();
        for (String group : groups) {
            arr.add(group);
        }
        return Response.ok(arr).build();
    }

    @Path("isMember")
    @GET
    public Response isMember(@QueryParam("groupName") String groupName,
            @QueryParam("userName") String userName, @HeaderParam("auth_token") String authToken) {
        if (authToken == null) {
            return Response.status(409).entity("Authentication failed").build();
        }
        SearchableFileSystem sfs = sfss.get(authToken);

        if (sfs == null) {
            return Response.status(409).entity("Authentication failed").build();
        }
        Boolean isMember = sfs.isMember(groupName, userName);
        return Response.ok(isMember.toString()).build();
    }

    @Path("owner")
    @GET
    public Response owner(@QueryParam("fileName") String fileName,
            @HeaderParam("auth_token") String authToken) {
        if (authToken == null) {
            return Response.status(409).entity("Authentication failed").build();
        }
        SearchableFileSystem sfs = sfss.get(authToken);

        if (sfs == null) {
            return Response.status(409).entity("Authentication failed").build();
        }
        String owner;
        try {
            owner = sfs.elementOwner(FrontendPath.parse(fileName));
        } catch (PathNotFoundException e) {
            return Response.status(400).entity("The resource does not exist.").build();
        } catch (InpherRuntimeException e) {
            return Response.status(400).entity("An error occured. Please check: " + e.getMessage())
                    .build();
        }
        return Response.ok(owner).build();
    }

    @Path("addUser")
    @GET
    public Response addUser(@QueryParam("groupName") String groupName,
            @QueryParam("userName") String userName, @HeaderParam("auth_token") String authToken) {
        if (authToken == null) {
            return Response.status(409).entity("Authentication failed").build();
        }
        SearchableFileSystem sfs = sfss.get(authToken);

        if (sfs == null) {
            return Response.status(409).entity("Authentication failed").build();
        }
        try {
            sfs.addUser(groupName, userName);
        } catch (ExistingMemberException e) {
            return Response.status(400).entity("The user is already a part of the group.").build();
        }
        return Response.ok("user added").build();
    }

    @Path("revokeUser")
    @GET
    public Response revokeUser(@QueryParam("groupName") String groupName,
            @QueryParam("userName") String userName, @HeaderParam("auth_token") String authToken) {
        if (authToken == null) {
            return Response.status(409).entity("Authentication failed").build();
        }
        SearchableFileSystem sfs = sfss.get(authToken);

        if (sfs == null) {
            return Response.status(409).entity("Authentication failed").build();
        }
        sfs.revokeUser(groupName, userName);
        return Response.ok("user revoked").build();
    }

    @Path("shareElement")
    @GET
    public Response shareElement(@QueryParam("groupName") String groupName,
            @QueryParam("filePath") String filePath, @QueryParam("shareName") String shareName,
            @HeaderParam("auth_token") String authToken) {
        if (authToken == null) {
            return Response.status(409).entity("Authentication failed").build();
        }
        SearchableFileSystem sfs = sfss.get(authToken);

        if (sfs == null) {
            return Response.status(409).entity("Authentication failed").build();
        }
        try {
            sfs.shareElement(groupName, FrontendPath.parse(filePath), shareName);
        } catch (ElementAlreadySharedException e) {
            return Response.status(400).entity("The element is already shared.").build();
        } catch (PathNotOwnedByUserException e) {
            return Response.status(400).entity("You can share only your own resources.").build();
        } catch (PathNotFoundException e) {
            return Response.status(400).entity("The resource does not exist.").build();
        } catch (InpherRuntimeException e) {
            return Response.status(400).entity("An error occured. Please check: " + e.getMessage())
                    .build();
        }
        return Response.ok("element shared").build();
    }

    @Path("unshareElement")
    @GET
    public Response unshareElement(@QueryParam("groupName") String groupName,
            @QueryParam("shareName") String shareName,
            @HeaderParam("auth_token") String authToken) {
        if (authToken == null) {
            return Response.status(409).entity("Authentication failed").build();
        }
        SearchableFileSystem sfs = sfss.get(authToken);

        if (sfs == null) {
            return Response.status(409).entity("Authentication failed").build();
        }
        try {
            sfs.unshareElement(groupName, shareName);
        } catch (ElementAlreadySharedException e) {
            return Response.status(400).entity("The element is already shared.").build();
        } catch (PathNotOwnedByUserException e) {
            return Response.status(400).entity("You can share only your own resources.").build();
        } catch (PathNotFoundException e) {
            return Response.status(400).entity("The resource does not exist.").build();
        } catch (InpherRuntimeException e) {
            return Response.status(400).entity("An error occured. Please check: " + e.getMessage())
                    .build();
        }
        return Response.ok("element unshared").build();
    }

    @Path("refreshGroupKeyring")
    @GET
    public Response refreshGroupKeyring(@QueryParam("groupName") String groupName,
            @HeaderParam("auth_token") String authToken) {
        if (authToken == null) {
            return Response.status(409).entity("Authentication failed").build();
        }
        SearchableFileSystem sfs = sfss.get(authToken);

        if (sfs == null) {
            return Response.status(409).entity("Authentication failed").build();
        }
        sfs.refreshGroupKeyring(groupName);
        return Response.ok("group keyring is refreshed").build();
    }

    @Path("refreshUserKeyring")
    @POST
    public Response refreshUserKeyring(@FormParam("password") String password,
            @HeaderParam("auth_token") String authToken) {
        if (authToken == null) {
            return Response.status(409).entity("Authentication failed").build();
        }
        SearchableFileSystem sfs = sfss.get(authToken);

        if (sfs == null) {
            return Response.status(409).entity("Authentication failed").build();
        }
        sfs.refreshUserKeyring(password);
        return Response.ok("user keyring is refreshed").build();
    }
}
