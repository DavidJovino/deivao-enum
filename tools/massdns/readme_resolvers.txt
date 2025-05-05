O resolvers.txt tem 17 resolvers confiáveis, focado em:

    Estabilidade

    Velocidade comprovada

    Distribuição geográfica segura

A ideia foi garantir uma lista que funcione sem bloqueios, throttling ou falsos positivos, já que listas muito grandes (com 100+ resolvers) podem causar problemas, como:

    Respostas inconsistentes ou lentas

    DNSs maliciosos ou instáveis (com TTL zero, NXDOMAIN falso)

    Rate limit por IP quando você usa todos ao mesmo tempo com massdns

Já o resolvers_full.txt vem do comando:

    curl -s https://public-dns.info/nameservers.txt -o resolvers.txt

Essa lista vem de https://public-dns.info, atualizada diariamente com DNSs públicos ao redor do mundo.

Caso for utilizar o full recomendo usar um script que testa a latência dos resolvers e ordena pelos mais rápidos que será implementado futuramente.