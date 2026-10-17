package dev.fenn.imessage.registration

/** The nac-oracle session vectors (expired session material, no identity data),
 * base64-embedded per the PearTablesData convention — no binaries in the repo. */
internal object PearOracleVectors {
    val estkeyarg: ByteArray by lazy {
        java.util.Base64.getDecoder().decode(
            "+eRK35/ix0GWWLsCwz7bywAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
        )
    }

    val estkeyret: ByteArray by lazy {
        java.util.Base64.getDecoder().decode(
            "+eRK35/ix0GWWLsCwz7bywQ+agZU7dnNQVwS1aOKpbufzfEXyyAo2op8Og8p9p+0K5ejmeC3i0Nq" +
            "y7FMQz0u+NSb1Oo0LF+pXufu5R3awB2hNEt6lRgU08v/+jbWJTorE3YPeYZuG6pNkeGcm7Tbt4dv" +
            "LDcBATedTJDWAdckDbZy9kroc/d9dT9nq3ToQ6bC57hXvpRPKsurKIG/Q2snfRyV8I4i0A8wANx5" +
            "1Y2GmZAAAAAAAAAAAABguda1BQAAXqHhzf9/AAAAn1nWtQUAABhmZe3/fwAAWH+Azv9/AABAKV7W" +
            "tQUAAEApXta1BQAAICC6ef9/AAANAAAAAAAAgCggunn/fwAAAAAAAAAAAAANAAAAAAAAgAAAAAAA" +
            "AACAfh/Rzf9/AAAEAAAAAAAAACBpW9a1BQAAAgAAAAAAAADDAAAAAAAAAAAAAAAAAAAAAAEBAQAA" +
            "AgAAALnWtQUAAAAgAAAAAAAAwwAAAAAAAADvBAAAAAAAAO8EAAAAAAAAAGC51rUFAADvBAAAAAAA" +
            "AO8EAAAAAAAABQAAAAAAAIC7AgAAAAAAAAcAAAAAAACAOCggunn/fwAAAAAAAAAAAAAAAAAAAAAA" +
            "AAAAAAAAAACAyCnWtQUAACAAAAAAAAAAuCa6ef9/AAC4Jrp5/38AACAgunn/fwAAAAAAAAAAAAAA" +
            "AAAAAAAAAA0AAAAAAACAz3bUzf9/AAAAAAAAAAAAAAABngJRYBwL7wQAAAAAAAC7AgAAAAAAAAMA" +
            "AAAAAACAKAAAAAAAAAAoGrp5KBq6eQAAAAAAAAAAGAAAAAAAAAAAPA7WtQUAAA0AAAAAAAAAAAAA" +
            "AAAAAAACAAAAAAAAAFBBBda1BQAAAAAAAAAAAAAAb1vWtQUAAABvAda1BQAAODQi1rUFAAAAAAAA" +
            "AAAAAFGb4c3/fwAAAgAAAAAAAIAAAAAAAAAAACgaunkoGrp5AAAAAAAAAAC6AgAAAAAAACggunn/" +
            "fwAAQCC6ef9/AAAAMSLWtQUAALsCAAAAAAAAAAAAAAAAAIBwK7p5/38AALoCAAAAAAAAAG8B1rUF" +
            "AAA0cOLN/38AAAAAAAAAAACAAGC51rUFAABXAAAAAAAAAOACu3n/fwAAgDQV1rUFAAA+AAAAAAAA" +
            "ACcnJycnJycnoEV6zv9/AAAnJycnJycnJ6Afunn/fwAAAAAAAAAAAIBQILp5/38AACAFAAAAAAAA" +
            "ACpW1rUFAAC/AgAAAAAAAGexJ87/fwAAwBgL1rUFAAAIAAAAAAAAgD4AAAAAAAAADQ0NDQ0NDQ0N" +
            "DQ0NDQ0NDQ3/U3r//0h9RmBOWiB1/ycLAAAAAAAAAPoAAAAAAAAA+eRK35/ix0GWWLsCwz7byw=="
        )
    }

    val sessinfo: ByteArray by lazy {
        java.util.Base64.getDecoder().decode(
            "AsadrYjF9AEQXXPfgnn4fvcAAAJQokzeoCROt5CkfQ0OQCOraCMcqNYu5PEXEbeal8FtwET+2zYj" +
            "m8z7SF7Fl4ZeJe2p8Id7sgTYNii/BTgSAnhiErQIazgaHKZDSrbhBAWawR9ZzbdlCkJSszzn9g/u" +
            "aPrHwODsU3MMcd10+3u8NGaAer1qx7WRW5gAnF7szRQk6dziZlHukYFmi8HWVPnyDnZcEkH21hdK" +
            "6No0GrReM/L1toRbHHp+iS8TdAb1Xhc5Uu0p3WcoBckiUmiPAHWgAEINU3/tV9r6z0A7G5IBr9VV" +
            "A+FwwwOaSZIH5Pi0EVrH+a6XML5o72+p10mr0uTRB0bbvViVR0IkC2c3g+OHD/xsKFJss/66ZlcN" +
            "hoBV6lWca5AuJuwmh1252X3cG+OLWwhLpHFrz16+9sTmhIwCGUE/qQ5qTOWTu3w83U7wrt7+ArJW" +
            "eoMIa4K4IA/NRKcoz58mAwULP2Ls9Wcv9POww+keJI+CsSR4P16J3nADBO7roVYe0aY47p1CSQaD" +
            "KP/6AP0pwIRDL573/7qvmCxMnHbG8SAhDhCOPc7wOBLlchKvn8s/yU7qFecKvi5GsKS+T1cQleZL" +
            "WvZ34hvhUVCpjSXH1Y2tysgpojzuK/y9nke5deI/oFdbaKnkZvMXCe/3m/pP8sQKCtHCUgaVu2q9" +
            "0TFLASq/dgrqFG6S6czk2V6lZoreLhcMOOEzqGbya5dChfRu/krZ1H/ZxWvVHRSiFRqoSUgpDjZE" +
            "yDJRxrPxDkQEi5AxHwy878n6+G3ZLQ8NeFR3f0D9t6l9kjZTCJKec+uO3gF4rXkuF7kE+qnIEfh+" +
            "0su0RbsjrgAAADYBA6pw1vTTPYd/rxY1xX6m9eNqxnRyXF/NiV7RApcd46+QUuef17DtjXRv1B7T" +
            "Sm5gcdOSEPdXAEwAOAA="
        )
    }

    val body576: ByteArray by lazy {
        java.util.Base64.getDecoder().decode(
            "jnk8fZH1LHncOKkQkCFNNroevkiTaRyuaTrLrZZxe8soGtVOeZ8rJm1TuqUjIdRv4sTkx1kadtd8" +
            "Ebgtjo2VMpiWPxXKX/UAQWIBK5EzAnYxojbnwSO+xlfdjuO/XVv+CEZL3w8KFQpzOtLcwxxrA7qi" +
            "SKp9YU7+LQ8iIGpSy3IK5kBFev4XS3Y+1n+v+P+sEAsM9x6TG5ARI4eQVHR00fdv8o86Mjtx/KJE" +
            "IUtUO+tlhdPrX+sNPVxZzMVsmFOkHShuX4zJEvU5Xa5d6K8uxW8GGbwhLigYESuHgEQK/5qiwsfy" +
            "pYrQrwJVa77EDMw4y9fGVGmD9MPA96TMIiPAQuPRrdFWMh47JpXq2TMMtRA8gQR+aQIPhQd3TkU/" +
            "6zYLeXPb/wJf6SGSy0kgk8aE/tW7YwdRqey8SgAI+VnxZMSJ+19ocMCEAJDokSZqn6yJMsFHT1pL" +
            "3N2f2t16Pj6pBkqrsLbzmSbo+vpXC+L+X9Q7AhlLXN64oPGGYf1j8r3cnEKuG499J/2maDJOuJDa" +
            "g1e/MtBNQHsSVPBSh2ISt1u3UdgMOWwxOtQWUTCgERqZx8jmVfl0kOe+NMfGvnTUGXc4HhY8ISuM" +
            "vvbxRD7vNBxoVeAeNhmuuLhbGFzNkOa/NpfFZeHUhJlx8XfUA7t7KIcGSobGFfgevLpu4YmD0N3J" +
            "pqM5zZ51Xoe70Jf+ev2umXRnwFow97Zyp1gP2fbhYAzm9NBhwnKLDqG0fcFebk1D0G11gU89BunI" +
            "YKt5cNTn"
        )
    }

}
