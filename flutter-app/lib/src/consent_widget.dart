import 'package:flutter/material.dart';
import 'package:logger/logger.dart';

var logger = Logger();

class ConsentWidget extends StatefulWidget {
  final String title;
  final String textHtml; // Can be a long string of HTML or markdown
  final VoidCallback onAgree;
  final VoidCallback onDecline;

  const ConsentWidget({
    Key? key,
    required this.title,
    required this.textHtml,
    required this.onAgree,
    required this.onDecline,
  }) : super(key: key);

  @override
  State<ConsentWidget> createState() => _ConsentWidgetState();
}

class _ConsentWidgetState extends State<ConsentWidget> {
  final ScrollController _sc = ScrollController();
  bool _scrolledToEnd = false;

  @override
  void initState() {
    super.initState();
    _sc.addListener(_scrollListener);
    // Check if content is shorter than scroll view and set _scrolledToEnd initially
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (_sc.position.maxScrollExtent == 0) { // If there's no scroll, it's already "at end"
        setState(() => _scrolledToEnd = true);
      }
    });
  }

  void _scrollListener() {
    if (!_scrolledToEnd && _sc.position.pixels >= _sc.position.maxScrollExtent * 0.95) { // Adjusted for slight tolerance
      logger.d('Scrolled almost to end, enabling agree button.');
      setState(() => _scrolledToEnd = true);
    }
  }

  @override
  void dispose() {
    _sc.removeListener(_scrollListener);
    _sc.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: Text(widget.title)),
      body: Column(
        children: [
          Expanded(
            child: SingleChildScrollView(
              controller: _sc,
              padding: const EdgeInsets.all(16),
              child: Text(
                widget.textHtml, // In a real app, use flutter_html or markdown widget to render HTML/Markdown
                style: Theme.of(context).textTheme.bodyMedium,
              ),
            ),
          ),
          Padding(
            padding: const EdgeInsets.all(16.0),
            child: Row(
              mainAxisAlignment: MainAxisAlignment.spaceEvenly,
              children: [
                Expanded(
                  child: ElevatedButton(
                    onPressed: _scrolledToEnd ? widget.onAgree : null,
                    style: ElevatedButton.styleFrom(
                      padding: const EdgeInsets.symmetric(vertical: 12),
                      backgroundColor: _scrolledToEnd ? Colors.green : Colors.grey,
                    ),
                    child: const Text(
                      'ვეთანხმები',
                      style: TextStyle(fontSize: 18, color: Colors.white),
                    ),
                  ),
                ),
                const SizedBox(width: 16),
                Expanded(
                  child: TextButton(
                    onPressed: widget.onDecline,
                    style: TextButton.styleFrom(
                      padding: const EdgeInsets.symmetric(vertical: 12),
                    ),
                    child: const Text(
                      'უარყოფა',
                      style: TextStyle(fontSize: 18, color: Colors.red),
                    ),
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }
}