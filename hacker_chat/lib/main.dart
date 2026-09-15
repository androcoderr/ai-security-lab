import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;
import 'dart:convert';
import 'package:flutter_markdown/flutter_markdown.dart';

void main() => runApp(const HackerChatApp());

class HackerChatApp extends StatelessWidget {
  const HackerChatApp({Key? key}) : super(key: key);

  @override
  Widget build(BuildContext context) {
    return const MaterialApp(
      home: ChatScreen(),
      debugShowCheckedModeBanner: false,
    );
  }
}

class ChatScreen extends StatefulWidget {
  const ChatScreen({Key? key}) : super(key: key);

  @override
  _ChatScreenState createState() => _ChatScreenState();
}

class _ChatScreenState extends State<ChatScreen> {
  final TextEditingController _controller = TextEditingController();
  List<String> messages = [];
  bool isLoading = false;

  Future<void> sendMessage(String text) async {
    setState(() {
      messages.add("Sen: $text");
      isLoading = true;
    });
    _controller.clear();

    try {
      // ZAFİYETLİ API'YE BAĞLANTI (iOS Simülatör ve Mac için localhost)
      final response = await http.post(
        Uri.parse('http://localhost:5001/api/chat'),
        headers: {'Content-Type': 'application/json'},
        body: jsonEncode({'message': text}),
      );

      if (response.statusCode == 200) {
        final data = jsonDecode(utf8.decode(response.bodyBytes));
        setState(() {
          // ZAFİYET: Gelen cevabı filtrelemeden listeye ekliyoruz
          messages.add("Llama 3: ${data['reply']}");
        });
      }
    } catch (e) {
      setState(() {
        messages.add("Hata: $e");
      });
    } finally {
      setState(() {
        isLoading = false;
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Zafiyetli AI Sohbet'), backgroundColor: Colors.red[900]),
      body: Column(
        children: [
          Expanded(
            child: ListView.builder(
              itemCount: messages.length,
              itemBuilder: (context, index) {
                final msg = messages[index];
                final isUser = msg.startsWith("Sen:");
                // ZAFİYETİN TETİKLENDİĞİ YER: Markdown widget'ı zararlı linkleri doğrudan açar!
                return Container(
                  padding: const EdgeInsets.all(8.0),
                  color: isUser ? Colors.blue[100] : Colors.grey[200],
                  child: MarkdownBody(data: msg.replaceFirst(isUser ? "Sen: " : "Llama 3: ", "")),
                );
              },
            ),
          ),
          if (isLoading) const CircularProgressIndicator(),
          Padding(
            padding: const EdgeInsets.all(8.0),
            child: Row(
              children: [
                Expanded(
                  child: TextField(
                    controller: _controller,
                    decoration: const InputDecoration(hintText: "Mesaj yaz..."),
                  ),
                ),
                IconButton(
                  icon: const Icon(Icons.send),
                  onPressed: () => sendMessage(_controller.text),
                )
              ],
            ),
          )
        ],
      ),
    );
  }
}
