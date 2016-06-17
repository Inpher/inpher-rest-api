package rest.service;

import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

public class MultiMaps {

    public static <K, V> boolean multimapInsert(Map<K, Set<V>> map, K key, V value) {
        Set<V> a = map.get(key);
        if (a == null) {
            a = ConcurrentHashMap.newKeySet();
            map.put(key, a);
        }
        return a.add(value);
    }

    public static <K, V> boolean multimapRemove(Map<K, Set<V>> map, K key, V value) {
        Set<V> a = map.get(key);
        if (a == null)
            return false;
        boolean res = a.remove(value);
        if (res) {
            map.remove(key);
            if(!a.isEmpty()) {
                map.put(key, a);
            }
        }
        return res;
    }

    public static <K, V> boolean multimapContains(Map<K, Set<V>> map, K key, V value) {
        Set<V> a = map.get(key);
        if (a == null)
            return false;
        return a.contains(value);
    }

    public static <K, V> boolean multimapIsKeyEmpty(Map<K, Set<V>> map, K key) {
        Set<V> a = map.get(key);
        return (a == null);
    }

}
