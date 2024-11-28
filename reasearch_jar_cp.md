# Java ``-cp`` vs ``-jar``

``Java -cp`` und ``Java -jar`` verhalten sich unterschiedlich bei der Ausführung von Java Programmen, wenn es um den Umgang mit Abhängigkeiten und dem Aufbau des ``Runtime Environment`` geht.

## Java ``-cp`` Verhalten

Wenn man ``java -cp`` verwendet:

- Der ``Classpath`` wird explizit definiert und enthält eine Liste von Verzeichnissen, JAR-Dateien oder Klassen, die Java zur Laufzeit verwendet, um Klassen und Ressourcen zu lokalisieren.
- Der angegebene ``Classpath`` enthält keine Abhängigkeiten, die in der MANIFEST.MF-Datei des JAR unter dem Attribut Class-Path aufgeführt sind. Wenn das primäre JAR von anderen Bibliotheke abhäng, müssen diese explizit im -cp Wert aufgeführt werden.
- Wenn man Abhängigkeiten vergisst, dann bekommt man eine ``NoClassDefFoundError`` oder ``ClassNotFoundException``.

## Java ``-jar`` Verhalten

Wen man ``-jar`` verwendet:

- Java liest die ``MANIFEST.MF`` Datei innerhalb der JAR-Datei, die spezifiziert wurde.
- Wenn die ``MANIFEST.MF`` Datei ein ``Class-Path`` Attribut enthält, dann werden die abhängigen JARs aufgelistet. Diese Abhängigkeiten werden automatisch zum Laufzeit-Classpath hinzugefügt.
- Das ``Main-Class`` Attribut in der ``MANIFEST.MF`` spezifiziert den Einstiegspunkt für die Anwendung.

Aus diesem Grund, bekommt man normalerweise keine ``NoClassDefFoundError`` oder ``ClassNotFoundException`` Fehler, wenn diese automatisch via ``MANIFEST.MF`` hinzugefügt werden.

## Verhalten wenn sowohl ``-cp`` als auch ``-jar`` verwendet werden

``Java -cp`` und ``Java -jar`` können nicht direkt kombiniert werden, da beide Anweiseungen sich gegenseitig ausschließen. Falls beide zusammen verwendet werden, so hat ``-jar`` Vorrang und ``-cp`` wird ignoriert.

## Wie kann man die Probleme umgehen?

1. Wenn man eine ``JAR`` Datei benutzt und ``-cp`` verwenden möchte, dann darf man nicht ``-jar`` verwenden, sondern es so ausführen:

```
java -cp myapp.jar:mylibrary.jar com.example.MainClass
```

hier muss aber dafür gesorgt werden, dass alle Abhängigkeiten im ``Classpath`` aufgeführt sind. Mit einer ``FAT JAR`` Datei, kann man alle Abhängigkeiten in einer Datei zusammen.

2. Man kann die weiteren ``JAR`` Dateien in der ``MANIFEST.MF`` Datei hinzufügen mittels ``Class-Path`` Parameter, damit diese automatisch hinzugefügt werden.
   - dass kann auch im nachhinein gemacht werden mit den folgenden Befehlen:
   1. ``MANIFEST:MF`` extrahieren:
    ```
   jar xvf app.jar META-INF/MANIFEST.MF
   ```
   2. ``Class-Path`` Attribut hinzufügen:
    ```
    Manifest-Version: 1.0
    Main-Class: com.example.Main
    Class-Path: dependency.jar
    ```
    3. ``MANIFEST.MF`` wieder in die ``JAR`` Datei packen:
     ```
    jar uvfm app.jar META-INF/MANIFEST.MF
    ```
   -Anmerkung: Die ``MANIFEST.MF`` scheint nur einmal so überschrieben werden zu können.