package ch.admin.bj.swiyu.didtoolbox.model;

public enum CryptographicAlgorithm {
    ED25519("Ed25519"),
    P256("P-256");

    private final String name;

    CryptographicAlgorithm(String name) {
        this.name = name;
    }

    @Override
    public String toString() {
        return this.name;
    }
}
