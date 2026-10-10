package dev.krypt04mcg.service;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import dev.krypt04mcg.model.GroupRecord;
import dev.krypt04mcg.util.JsonSupport;
import dev.krypt04mcg.util.SecureFiles;

import java.io.IOException;
import java.lang.reflect.Type;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

public final class GroupService {
    private static final Type GROUPS_TYPE = new TypeToken<Map<String, GroupRecord>>() {
    }.getType();

    private final Path groupsFile;
    private final Gson gson = JsonSupport.prettyGson();

    /**
     * Creates a group service with the supplied dependencies and initial state.
     *
     * @param root the account or configuration storage root
     */
    public GroupService(Path root) {
        this.groupsFile = root.resolve("groups.json");
    }

    /**
     * Returns the recorded group for the group service.
     *
     * @param name the name supplied to this operation
     * @param members the members supplied to this operation
     * @return the result described above
     * @throws IOException if input/output, stored-state validation or resource handling fails
     */
    public synchronized GroupRecord create(String name, List<String> members) throws IOException {
        if (members.isEmpty()) {
            throw new IOException("Group must contain at least one member");
        }
        Map<String, GroupRecord> groups = readGroups();
        GroupRecord group = new GroupRecord(name, List.copyOf(members), Instant.now());
        groups.put(normalize(name), group);
        writeGroups(groups);
        return group;
    }

    /**
     * Looks up the requested entry in the group service without creating a replacement.
     *
     * @param name the name supplied to this operation
     * @return the result described above
     * @throws IOException if input/output, stored-state validation or resource handling fails
     */
    public synchronized Optional<GroupRecord> find(String name) throws IOException {
        return Optional.ofNullable(readGroups().get(normalize(name)));
    }

    /**
     * Performs the list operation for the group service.
     *
     * @return the result described above
     * @throws IOException if input/output, stored-state validation or resource handling fails
     */
    public synchronized List<GroupRecord> list() throws IOException {
        return new ArrayList<>(readGroups().values());
    }

    /**
     * Performs the delete operation for the group service.
     *
     * @param name the name supplied to this operation
     * @throws IOException if input/output, stored-state validation or resource handling fails
     */
    public synchronized void delete(String name) throws IOException {
        Map<String, GroupRecord> groups = readGroups();
        groups.remove(normalize(name));
        writeGroups(groups);
    }

    /**
     * Reads groups from the input used by the group service.
     *
     * @return the result described above
     * @throws IOException if input/output, stored-state validation or resource handling fails
     */
    private Map<String, GroupRecord> readGroups() throws IOException {
        SecureFiles.rejectLinks(groupsFile);
        if (!Files.exists(groupsFile)) {
            return new LinkedHashMap<>();
        }
        SecureFiles.restrictToOwner(groupsFile, false);
        Map<String, GroupRecord> groups = gson.fromJson(Files.readString(groupsFile, StandardCharsets.UTF_8), GROUPS_TYPE);
        return groups == null ? new LinkedHashMap<>() : new LinkedHashMap<>(groups);
    }

    /**
     * Writes groups to the output used by the group service.
     *
     * @param groups the groups supplied to this operation
     * @throws IOException if input/output, stored-state validation or resource handling fails
     */
    private void writeGroups(Map<String, GroupRecord> groups) throws IOException {
        SecureFiles.atomicWrite(groupsFile, gson.toJson(groups, GROUPS_TYPE).getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Normalizes the supplied identifier into the comparison/storage form used by the group service.
     *
     * @param name the name supplied to this operation
     * @return the result described above
     */
    private static String normalize(String name) {
        return name.toLowerCase(Locale.ROOT);
    }
}
