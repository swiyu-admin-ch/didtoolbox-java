package ch.admin.bj.swiyu.didtoolbox.model;

public enum CryptographicAlgorithm {
    ED25519("Ed25519"),
    ECP256("EcP-256");

    private final String name;

    CryptographicAlgorithm(String name) {
        this.name = name;
    }

    @Override
    public String toString() {
        return this.name;
    }
}
