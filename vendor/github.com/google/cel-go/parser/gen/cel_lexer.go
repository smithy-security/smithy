// Code generated from /usr/local/google/home/tswadell/go/src/github.com/google/cel-go/parser/gen/CEL.g4 by ANTLR 4.13.1. DO NOT EDIT.

package gen

import (
	"fmt"
	"sync"
	"unicode"

	"github.com/antlr4-go/antlr/v4"
)

// Suppress unused import error
var _ = fmt.Printf
var _ = sync.Once{}
var _ = unicode.IsLetter

type CELLexer struct {
	*antlr.BaseLexer
	channelNames []string
	modeNames    []string
	// TODO: EOF string
}

var CELLexerLexerStaticData struct {
	once                   sync.Once
	serializedATN          []int32
	ChannelNames           []string
	ModeNames              []string
	LiteralNames           []string
	SymbolicNames          []string
	RuleNames              []string
	PredictionContextCache *antlr.PredictionContextCache
	atn                    *antlr.ATN
	decisionToDFA          []*antlr.DFA
}

func cellexerLexerInit() {
	staticData := &CELLexerLexerStaticData
	staticData.ChannelNames = []string{
		"DEFAULT_TOKEN_CHANNEL", "HIDDEN",
	}
	staticData.ModeNames = []string{
		"DEFAULT_MODE",
	}
	staticData.LiteralNames = []string{
		"", "'=='", "'!='", "'in'", "'<'", "'<='", "'>='", "'>'", "'&&'", "'||'",
		"'['", "']'", "'{'", "'}'", "'('", "')'", "'.'", "','", "'-'", "'!'",
		"'?'", "':'", "'+'", "'*'", "'/'", "'%'", "'true'", "'false'", "'null'",
	}
	staticData.SymbolicNames = []string{
		"", "EQUALS", "NOT_EQUALS", "IN", "LESS", "LESS_EQUALS", "GREATER_EQUALS",
		"GREATER", "LOGICAL_AND", "LOGICAL_OR", "LBRACKET", "RPRACKET", "LBRACE",
		"RBRACE", "LPAREN", "RPAREN", "DOT", "COMMA", "MINUS", "EXCLAM", "QUESTIONMARK",
		"COLON", "PLUS", "STAR", "SLASH", "PERCENT", "CEL_TRUE", "CEL_FALSE",
		"NUL", "WHITESPACE", "COMMENT", "NUM_FLOAT", "NUM_INT", "NUM_UINT",
		"STRING", "BYTES", "IDENTIFIER",
	}
	staticData.RuleNames = []string{
		"EQUALS", "NOT_EQUALS", "IN", "LESS", "LESS_EQUALS", "GREATER_EQUALS",
		"GREATER", "LOGICAL_AND", "LOGICAL_OR", "LBRACKET", "RPRACKET", "LBRACE",
		"RBRACE", "LPAREN", "RPAREN", "DOT", "COMMA", "MINUS", "EXCLAM", "QUESTIONMARK",
		"COLON", "PLUS", "STAR", "SLASH", "PERCENT", "CEL_TRUE", "CEL_FALSE",
		"NUL", "BACKSLASH", "LETTER", "DIGIT", "EXPONENT", "HEXDIGIT", "RAW",
		"ESC_SEQ", "ESC_CHAR_SEQ", "ESC_OCT_SEQ", "ESC_BYTE_SEQ", "ESC_UNI_SEQ",
		"WHITESPACE", "COMMENT", "NUM_FLOAT", "NUM_INT", "NUM_UINT", "STRING",
		"BYTES", "IDENTIFIER",
	}
	staticData.PredictionContextCache = antlr.NewPredictionContextCache()
	staticData.serializedATN = []int32{
		4, 0, 36, 423, 6, -1, 2, 0, 7, 0, 2, 1, 7, 1, 2, 2, 7, 2, 2, 3, 7, 3, 2,
		4, 7, 4, 2, 5, 7, 5, 2, 6, 7, 6, 2, 7, 7, 7, 2, 8, 7, 8, 2, 9, 7, 9, 2,
		10, 7, 10, 2, 11, 7, 11, 2, 12, 7, 12, 2, 13, 7, 13, 2, 14, 7, 14, 2, 15,
		7, 15, 2, 16, 7, 16, 2, 17, 7, 17, 2, 18, 7, 18, 2, 19, 7, 19, 2, 20, 7,
		20, 2, 21, 7, 21, 2, 22, 7, 22, 2, 23, 7, 23, 2, 24, 7, 24, 2, 25, 7, 25,
		2, 26, 7, 26, 2, 27, 7, 27, 2, 28, 7, 28, 2, 29, 7, 29, 2, 30, 7, 30, 2,
		31, 7, 31, 2, 32, 7, 32, 2, 33, 7, 33, 2, 34, 7, 34, 2, 35, 7, 35, 2, 36,
		7, 36, 2, 37, 7, 37, 2, 38, 7, 38, 2, 39, 7, 39, 2, 40, 7, 40, 2, 41, 7,
		41, 2, 42, 7, 42, 2, 43, 7, 43, 2, 44, 7, 44, 2, 45, 7, 45, 2, 46, 7, 46,
		1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 2, 1, 2, 1, 2, 1, 3, 1, 3, 1, 4,
		1, 4, 1, 4, 1, 5, 1, 5, 1, 5, 1, 6, 1, 6, 1, 7, 1, 7, 1, 7, 1, 8, 1, 8,
		1, 8, 1, 9, 1, 9, 1, 10, 1, 10, 1, 11, 1, 11, 1, 12, 1, 12, 1, 13, 1, 13,
		1, 14, 1, 14, 1, 15, 1, 15, 1, 16, 1, 16, 1, 17, 1, 17, 1, 18, 1, 18, 1,
		19, 1, 19, 1, 20, 1, 20, 1, 21, 1, 21, 1, 22, 1, 22, 1, 23, 1, 23, 1, 24,
		1, 24, 1, 25, 1, 25, 1, 25, 1, 25, 1, 25, 1, 26, 1, 26, 1, 26, 1, 26, 1,
		26, 1, 26, 1, 27, 1, 27, 1, 27, 1, 27, 1, 27, 1, 28, 1, 28, 1, 29, 1, 29,
		1, 30, 1, 30, 1, 31, 1, 31, 3, 31, 177, 8, 31, 1, 31, 4, 31, 180, 8, 31,
		11, 31, 12, 31, 181, 1, 32, 1, 32, 1, 33, 1, 33, 1, 34, 1, 34, 1, 34, 1,
		34, 3, 34, 192, 8, 34, 1, 35, 1, 35, 1, 35, 1, 36, 1, 36, 1, 36, 1, 36,
		1, 36, 1, 37, 1, 37, 1, 37, 1, 37, 1, 37, 1, 38, 1, 38, 1, 38, 1, 38, 1,
		38, 1, 38, 1, 38, 1, 38, 1, 38, 1, 38, 1, 38, 1, 38, 1, 38, 1, 38, 1, 38,
		1, 38, 1, 38, 1, 38, 3, 38, 225, 8, 38, 1, 39, 4, 39, 228, 8, 39, 11, 39,
		12, 39, 229, 1, 39, 1, 39, 1, 40, 1, 40, 1, 40, 1, 40, 5, 40, 238, 8, 40,
		10, 40, 12, 40, 241, 9, 40, 1, 40, 1, 40, 1, 41, 4, 41, 246, 8, 41, 11,
		41, 12, 41, 247, 1, 41, 1, 41, 4, 41, 252, 8, 41, 11, 41, 12, 41, 253,
		1, 41, 3, 41, 257, 8, 41, 1, 41, 4, 41, 260, 8, 41, 11, 41, 12, 41, 261,
		1, 41, 1, 41, 1, 41, 1, 41, 4, 41, 268, 8, 41, 11, 41, 12, 41, 269, 1,
		41, 3, 41, 273, 8, 41, 3, 41, 275, 8, 41, 1, 42, 4, 42, 278, 8, 42, 11,
		42, 12, 42, 279, 1, 42, 1, 42, 1, 42, 1, 42, 4, 42, 286, 8, 42, 11, 42,
		12, 42, 287, 3, 42, 290, 8, 42, 1, 43, 4, 43, 293, 8, 43, 11, 43, 12, 43,
		294, 1, 43, 1, 43, 1, 43, 1, 43, 1, 43, 1, 43, 4, 43, 303, 8, 43, 11, 43,
		12, 43, 304, 1, 43, 1, 43, 3, 43, 309, 8, 43, 1, 44, 1, 44, 1, 44, 5, 44,
		314, 8, 44, 10, 44, 12, 44, 317, 9, 44, 1, 44, 1, 44, 1, 44, 1, 44, 5,
		44, 323, 8, 44, 10, 44, 12, 44, 326, 9, 44, 1, 44, 1, 44, 1, 44, 1, 44,
		1, 44, 1, 44, 1, 44, 5, 44, 335, 8, 44, 10, 44, 12, 44, 338, 9, 44, 1,
		44, 1, 44, 1, 44, 1, 44, 1, 44, 1, 44, 1, 44, 1, 44, 1, 44, 5, 44, 349,
		8, 44, 10, 44, 12, 44, 352, 9, 44, 1, 44, 1, 44, 1, 44, 1, 44, 1, 44, 1,
		44, 5, 44, 360, 8, 44, 10, 44, 12, 44, 363, 9, 44, 1, 44, 1, 44, 1, 44,
		1, 44, 1, 44, 5, 44, 370, 8, 44, 10, 44, 12, 44, 373, 9, 44, 1, 44, 1,
		44, 1, 44, 1, 44, 1, 44, 1, 44, 1, 44, 1, 44, 5, 44, 383, 8, 44, 10, 44,
		12, 44, 386, 9, 44, 1, 44, 1, 44, 1, 44, 1, 44, 1, 44, 1, 44, 1, 44, 1,
		44, 1, 44, 1, 44, 5, 44, 398, 8, 44, 10, 44, 12, 44, 401, 9, 44, 1, 44,
		1, 44, 1, 44, 1, 44, 3, 44, 407, 8, 44, 1, 45, 1, 45, 1, 45, 1, 46, 1,
		46, 3, 46, 414, 8, 46, 1, 46, 1, 46, 1, 46, 5, 46, 419, 8, 46, 10, 46,
		12, 46, 422, 9, 46, 4, 336, 350, 384, 399, 0, 47, 1, 1, 3, 2, 5, 3, 7,
		4, 9, 5, 11, 6, 13, 7, 15, 8, 17, 9, 19, 10, 21, 11, 23, 12, 25, 13, 27,
		14, 29, 15, 31, 16, 33, 17, 35, 18, 37, 19, 39, 20, 41, 21, 43, 22, 45,
		23, 47, 24, 49, 25, 51, 26, 53, 27, 55, 28, 57, 0, 59, 0, 61, 0, 63, 0,
		65, 0, 67, 0, 69, 0, 71, 0, 73, 0, 75, 0, 77, 0, 79, 29, 81, 30, 83, 31,
		85, 32, 87, 33, 89, 34, 91, 35, 93, 36, 1, 0, 16, 2, 0, 65, 90, 97, 122,
		2, 0, 69, 69, 101, 101, 2, 0, 43, 43, 45, 45, 3, 0, 48, 57, 65, 70, 97,
		102, 2, 0, 82, 82, 114, 114, 10, 0, 34, 34, 39, 39, 63, 63, 92, 92, 96,
		98, 102, 102, 110, 110, 114, 114, 116, 116, 118, 118, 2, 0, 88, 88, 120,
		120, 3, 0, 9, 10, 12, 13, 32, 32, 1, 0, 10, 10, 2, 0, 85, 85, 117, 117,
		4, 0, 10, 10, 13, 13, 34, 34, 92, 92, 4, 0, 10, 10, 13, 13, 39, 39, 92,
		92, 1, 0, 92, 92, 3, 0, 10, 10, 13, 13, 34, 34, 3, 0, 10, 10, 13, 13, 39,
		39, 2, 0, 66, 66, 98, 98, 456, 0, 1, 1, 0, 0, 0, 0, 3, 1, 0, 0, 0, 0, 5,
		1, 0, 0, 0, 0, 7, 1, 0, 0, 0, 0, 9, 1, 0, 0, 0, 0, 11, 1, 0, 0, 0, 0, 13,
		1, 0, 0, 0, 0, 15, 1, 0, 0, 0, 0, 17, 1, 0, 0, 0, 0, 19, 1, 0, 0, 0, 0,
		21, 1, 0, 0, 0, 0, 23, 1, 0, 0, 0, 0, 25, 1, 0, 0, 0, 0, 27, 1, 0, 0, 0,
		0, 29, 1, 0, 0, 0, 0, 31, 1, 0, 0, 0, 0, 33, 1, 0, 0, 0, 0, 35, 1, 0, 0,
		0, 0, 37, 1, 0, 0, 0, 0, 39, 1, 0, 0, 0, 0, 41, 1, 0, 0, 0, 0, 43, 1, 0,
		0, 0, 0, 45, 1, 0, 0, 0, 0, 47, 1, 0, 0, 0, 0, 49, 1, 0, 0, 0, 0, 51, 1,
		0, 0, 0, 0, 53, 1, 0, 0, 0, 0, 55, 1, 0, 0, 0, 0, 79, 1, 0, 0, 0, 0, 81,
		1, 0, 0, 0, 0, 83, 1, 0, 0, 0, 0, 85, 1, 0, 0, 0, 0, 87, 1, 0, 0, 0, 0,
		89, 1, 0, 0, 0, 0, 91, 1, 0, 0, 0, 0, 93, 1, 0, 0, 0, 1, 95, 1, 0, 0, 0,
		3, 98, 1, 0, 0, 0, 5, 101, 1, 0, 0, 0, 7, 104, 1, 0, 0, 0, 9, 106, 1, 0,
		0, 0, 11, 109, 1, 0, 0, 0, 13, 112, 1, 0, 0, 0, 15, 114, 1, 0, 0, 0, 17,
		117, 1, 0, 0, 0, 19, 120, 1, 0, 0, 0, 21, 122, 1, 0, 0, 0, 23, 124, 1,
		0, 0, 0, 25, 126, 1, 0, 0, 0, 27, 128, 1, 0, 0, 0, 29, 130, 1, 0, 0, 0,
		31, 132, 1, 0, 0, 0, 33, 134, 1, 0, 0, 0, 35, 136, 1, 0, 0, 0, 37, 138,
		1, 0, 0, 0, 39, 140, 1, 0, 0, 0, 41, 142, 1, 0, 0, 0, 43, 144, 1, 0, 0,
		0, 45, 146, 1, 0, 0, 0, 47, 148, 1, 0, 0, 0, 49, 150, 1, 0, 0, 0, 51, 152,
		1, 0, 0, 0, 53, 157, 1, 0, 0, 0, 55, 163, 1, 0, 0, 0, 57, 168, 1, 0, 0,
		0, 59, 170, 1, 0, 0, 0, 61, 172, 1, 0, 0, 0, 63, 174, 1, 0, 0, 0, 65, 183,
		1, 0, 0, 0, 67, 185, 1, 0, 0, 0, 69, 191, 1, 0, 0, 0, 71, 193, 1, 0, 0,
		0, 73, 196, 1, 0, 0, 0, 75, 201, 1, 0, 0, 0, 77, 224, 1, 0, 0, 0, 79, 227,
		1, 0, 0, 0, 81, 233, 1, 0, 0, 0, 83, 274, 1, 0, 0, 0, 85, 289, 1, 0, 0,
		0, 87, 308, 1, 0, 0, 0, 89, 406, 1, 0, 0, 0, 91, 408, 1, 0, 0, 0, 93, 413,
		1, 0, 0, 0, 95, 96, 5, 61, 0, 0, 96, 97, 5, 61, 0, 0, 97, 2, 1, 0, 0, 0,
		98, 99, 5, 33, 0, 0, 99, 100, 5, 61, 0, 0, 100, 4, 1, 0, 0, 0, 101, 102,
		5, 105, 0, 0, 102, 103, 5, 110, 0, 0, 103, 6, 1, 0, 0, 0, 104, 105, 5,
		60, 0, 0, 105, 8, 1, 0, 0, 0, 106, 107, 5, 60, 0, 0, 107, 108, 5, 61, 0,
		0, 108, 10, 1, 0, 0, 0, 109, 110, 5, 62, 0, 0, 110, 111, 5, 61, 0, 0, 111,
		12, 1, 0, 0, 0, 112, 113, 5, 62, 0, 0, 113, 14, 1, 0, 0, 0, 114, 115, 5,
		38, 0, 0, 115, 116, 5, 38, 0, 0, 116, 16, 1, 0, 0, 0, 117, 118, 5, 124,
		0, 0, 118, 119, 5, 124, 0, 0, 119, 18, 1, 0, 0, 0, 120, 121, 5, 91, 0,
		0, 121, 20, 1, 0, 0, 0, 122, 123, 5, 93, 0, 0, 123, 22, 1, 0, 0, 0, 124,
		125, 5, 123, 0, 0, 125, 24, 1, 0, 0, 0, 126, 127, 5, 125, 0, 0, 127, 26,
		1, 0, 0, 0, 128, 129, 5, 40, 0, 0, 129, 28, 1, 0, 0, 0, 130, 131, 5, 41,
		0, 0, 131, 30, 1, 0, 0, 0, 132, 133, 5, 46, 0, 0, 133, 32, 1, 0, 0, 0,
		134, 135, 5, 44, 0, 0, 135, 34, 1, 0, 0, 0, 136, 137, 5, 45, 0, 0, 137,
		36, 1, 0, 0, 0, 138, 139, 5, 33, 0, 0, 139, 38, 1, 0, 0, 0, 140, 141, 5,
		63, 0, 0, 141, 40, 1, 0, 0, 0, 142, 143, 5, 58, 0, 0, 143, 42, 1, 0, 0,
		0, 144, 145, 5, 43, 0, 0, 145, 44, 1, 0, 0, 0, 146, 147, 5, 42, 0, 0, 147,
		46, 1, 0, 0, 0, 148, 149, 5, 47, 0, 0, 149, 48, 1, 0, 0, 0, 150, 151, 5,
		37, 0, 0, 151, 50, 1, 0, 0, 0, 152, 153, 5, 116, 0, 0, 153, 154, 5, 114,
		0, 0, 154, 155, 5, 117, 0, 0, 155, 156, 5, 101, 0, 0, 156, 52, 1, 0, 0,
		0, 157, 158, 5, 102, 0, 0, 158, 159, 5, 97, 0, 0, 159, 160, 5, 108, 0,
		0, 160, 161, 5, 115, 0, 0, 161, 162, 5, 101, 0, 0, 162, 54, 1, 0, 0, 0,
		163, 164, 5, 110, 0, 0, 164, 165, 5, 117, 0, 0, 165, 166, 5, 108, 0, 0,
		166, 167, 5, 108, 0, 0, 167, 56, 1, 0, 0, 0, 168, 169, 5, 92, 0, 0, 169,
		58, 1, 0, 0, 0, 170, 171, 7, 0, 0, 0, 171, 60, 1, 0, 0, 0, 172, 173, 2,
		48, 57, 0, 173, 62, 1, 0, 0, 0, 174, 176, 7, 1, 0, 0, 175, 177, 7, 2, 0,
		0, 176, 175, 1, 0, 0, 0, 176, 177, 1, 0, 0, 0, 177, 179, 1, 0, 0, 0, 178,
		180, 3, 61, 30, 0, 179, 178, 1, 0, 0, 0, 180, 181, 1, 0, 0, 0, 181, 179,
		1, 0, 0, 0, 181, 182, 1, 0, 0, 0, 182, 64, 1, 0, 0, 0, 183, 184, 7, 3,
		0, 0, 184, 66, 1, 0, 0, 0, 185, 186, 7, 4, 0, 0, 186, 68, 1, 0, 0, 0, 187,
		192, 3, 71, 35, 0, 188, 192, 3, 75, 37, 0, 189, 192, 3, 77, 38, 0, 190,
		192, 3, 73, 36, 0, 191, 187, 1, 0, 0, 0, 191, 188, 1, 0, 0, 0, 191, 189,
		1, 0, 0, 0, 191, 190, 1, 0, 0, 0, 192, 70, 1, 0, 0, 0, 193, 194, 3, 57,
		28, 0, 194, 195, 7, 5, 0, 0, 195, 72, 1, 0, 0, 0, 196, 197, 3, 57, 28,
		0, 197, 198, 2, 48, 51, 0, 198, 199, 2, 48, 55, 0, 199, 200, 2, 48, 55,
		0, 200, 74, 1, 0, 0, 0, 201, 202, 3, 57, 28, 0, 202, 203, 7, 6, 0, 0, 203,
		204, 3, 65, 32, 0, 204, 205, 3, 65, 32, 0, 205, 76, 1, 0, 0, 0, 206, 207,
		3, 57, 28, 0, 207, 208, 5, 117, 0, 0, 208, 209, 3, 65, 32, 0, 209, 210,
		3, 65, 32, 0, 210, 211, 3, 65, 32, 0, 211, 212, 3, 65, 32, 0, 212, 225,
		1, 0, 0, 0, 213, 214, 3, 57, 28, 0, 214, 215, 5, 85, 0, 0, 215, 216, 3,
		65, 32, 0, 216, 217, 3, 65, 32, 0, 217, 218, 3, 65, 32, 0, 218, 219, 3,
		65, 32, 0, 219, 220, 3, 65, 32, 0, 220, 221, 3, 65, 32, 0, 221, 222, 3,
		65, 32, 0, 222, 223, 3, 65, 32, 0, 223, 225, 1, 0, 0, 0, 224, 206, 1, 0,
		0, 0, 224, 213, 1, 0, 0, 0, 225, 78, 1, 0, 0, 0, 226, 228, 7, 7, 0, 0,
		227, 226, 1, 0, 0, 0, 228, 229, 1, 0, 0, 0, 229, 227, 1, 0, 0, 0, 229,
		230, 1, 0, 0, 0, 230, 231, 1, 0, 0, 0, 231, 232, 6, 39, 0, 0, 232, 80,
		1, 0, 0, 0, 233, 234, 5, 47, 0, 0, 234, 235, 5, 47, 0, 0, 235, 239, 1,
		0, 0, 0, 236, 238, 8, 8, 0, 0, 237, 236, 1, 0, 0, 0, 238, 241, 1, 0, 0,
		0, 239, 237, 1, 0, 0, 0, 239, 240, 1, 0, 0, 0, 240, 242, 1, 0, 0, 0, 241,
		239, 1, 0, 0, 0, 242, 243, 6, 40, 0, 0, 243, 82, 1, 0, 0, 0, 244, 246,
		3, 61, 30, 0, 245, 244, 1, 0, 0, 0, 246, 247, 1, 0, 0, 0, 247, 245, 1,
		0, 0, 0, 247, 248, 1, 0, 0, 0, 248, 249, 1, 0, 0, 0, 249, 251, 5, 46, 0,
		0, 250, 252, 3, 61, 30, 0, 251, 250, 1, 0, 0, 0, 252, 253, 1, 0, 0, 0,
		253, 251, 1, 0, 0, 0, 253, 254, 1, 0, 0, 0, 254, 256, 1, 0, 0, 0, 255,
		257, 3, 63, 31, 0, 256, 255, 1, 0, 0, 0, 256, 257, 1, 0, 0, 0, 257, 275,
		1, 0, 0, 0, 258, 260, 3, 61, 30, 0, 259, 258, 1, 0, 0, 0, 260, 261, 1,
		0, 0, 0, 261, 259, 1, 0, 0, 0, 261, 262, 1, 0, 0, 0, 262, 263, 1, 0, 0,
		0, 263, 264, 3, 63, 31, 0, 264, 275, 1, 0, 0, 0, 265, 267, 5, 46, 0, 0,
		266, 268, 3, 61, 30, 0, 267, 266, 1, 0, 0, 0, 268, 269, 1, 0, 0, 0, 269,
		267, 1, 0, 0, 0, 269, 270, 1, 0, 0, 0, 270, 272, 1, 0, 0, 0, 271, 273,
		3, 63, 31, 0, 272, 271, 1, 0, 0, 0, 272, 273, 1, 0, 0, 0, 273, 275, 1,
		0, 0, 0, 274, 245, 1, 0, 0, 0, 274, 259, 1, 0, 0, 0, 274, 265, 1, 0, 0,
		0, 275, 84, 1, 0, 0, 0, 276, 278, 3, 61, 30, 0, 277, 276, 1, 0, 0, 0, 278,
		279, 1, 0, 0, 0, 279, 277, 1, 0, 0, 0, 279, 280, 1, 0, 0, 0, 280, 290,
		1, 0, 0, 0, 281, 282, 5, 48, 0, 0, 282, 283, 5, 120, 0, 0, 283, 285, 1,
		0, 0, 0, 284, 286, 3, 65, 32, 0, 285, 284, 1, 0, 0, 0, 286, 287, 1, 0,
		0, 0, 287, 285, 1, 0, 0, 0, 287, 288, 1, 0, 0, 0, 288, 290, 1, 0, 0, 0,
		289, 277, 1, 0, 0, 0, 289, 281, 1, 0, 0, 0, 290, 86, 1, 0, 0, 0, 291, 293,
		3, 61, 30, 0, 292, 291, 1, 0, 0, 0, 293, 294, 1, 0, 0, 0, 294, 292, 1,
		0, 0, 0, 294, 295, 1, 0, 0, 0, 295, 296, 1, 0, 0, 0, 296, 297, 7, 9, 0,
		0, 297, 309, 1, 0, 0, 0, 298, 299, 5, 48, 0, 0, 299, 300, 5, 120, 0, 0,
		300, 302, 1, 0, 0, 0, 301, 303, 3, 65, 32, 0, 302, 301, 1, 0, 0, 0, 303,
		304, 1, 0, 0, 0, 304, 302, 1, 0, 0, 0, 304, 305, 1, 0, 0, 0, 305, 306,
		1, 0, 0, 0, 306, 307, 7, 9, 0, 0, 307, 309, 1, 0, 0, 0, 308, 292, 1, 0,
		0, 0, 308, 298, 1, 0, 0, 0, 309, 88, 1, 0, 0, 0, 310, 315, 5, 34, 0, 0,
		311, 314, 3, 69, 34, 0, 312, 314, 8, 10, 0, 0, 313, 311, 1, 0, 0, 0, 313,
		312, 1, 0, 0, 0, 314, 317, 1, 0, 0, 0, 315, 313, 1, 0, 0, 0, 315, 316,
		1, 0, 0, 0, 316, 318, 1, 0, 0, 0, 317, 315, 1, 0, 0, 0, 318, 407, 5, 34,
		0, 0, 319, 324, 5, 39, 0, 0, 320, 323, 3, 69, 34, 0, 321, 323, 8, 11, 0,
		0, 322, 320, 1, 0, 0, 0, 322, 321, 1, 0, 0, 0, 323, 326, 1, 0, 0, 0, 324,
		322, 1, 0, 0, 0, 324, 325, 1, 0, 0, 0, 325, 327, 1, 0, 0, 0, 326, 324,
		1, 0, 0, 0, 327, 407, 5, 39, 0, 0, 328, 329, 5, 34, 0, 0, 329, 330, 5,
		34, 0, 0, 330, 331, 5, 34, 0, 0, 331, 336, 1, 0, 0, 0, 332, 335, 3, 69,
		34, 0, 333, 335, 8, 12, 0, 0, 334, 332, 1, 0, 0, 0, 334, 333, 1, 0, 0,
		0, 335, 338, 1, 0, 0, 0, 336, 337, 1, 0, 0, 0, 336, 334, 1, 0, 0, 0, 337,
		339, 1, 0, 0, 0, 338, 336, 1, 0, 0, 0, 339, 340, 5, 34, 0, 0, 340, 341,
		5, 34, 0, 0, 341, 407, 5, 34, 0, 0, 342, 343, 5, 39, 0, 0, 343, 344, 5,
		39, 0, 0, 344, 345, 5, 39, 0, 0, 345, 350, 1, 0, 0, 0, 346, 349, 3, 69,
		34, 0, 347, 349, 8, 12, 0, 0, 348, 346, 1, 0, 0, 0, 348, 347, 1, 0, 0,
		0, 349, 352, 1, 0, 0, 0, 350, 351, 1, 0, 0, 0, 350, 348, 1, 0, 0, 0, 351,
		353, 1, 0, 0, 0, 352, 350, 1, 0, 0, 0, 353, 354, 5, 39, 0, 0, 354, 355,
		5, 39, 0, 0, 355, 407, 5, 39, 0, 0, 356, 357, 3, 67, 33, 0, 357, 361, 5,
		34, 0, 0, 358, 360, 8, 13, 0, 0, 359, 358, 1, 0, 0, 0, 360, 363, 1, 0,
		0, 0, 361, 359, 1, 0, 0, 0, 361, 362, 1, 0, 0, 0, 362, 364, 1, 0, 0, 0,
		363, 361, 1, 0, 0, 0, 364, 365, 5, 34, 0, 0, 365, 407, 1, 0, 0, 0, 366,
		367, 3, 67, 33, 0, 367, 371, 5, 39, 0, 0, 368, 370, 8, 14, 0, 0, 369, 368,
		1, 0, 0, 0, 370, 373, 1, 0, 0, 0, 371, 369, 1, 0, 0, 0, 371, 372, 1, 0,
		0, 0, 372, 374, 1, 0, 0, 0, 373, 371, 1, 0, 0, 0, 374, 375, 5, 39, 0, 0,
		375, 407, 1, 0, 0, 0, 376, 377, 3, 67, 33, 0, 377, 378, 5, 34, 0, 0, 378,
		379, 5, 34, 0, 0, 379, 380, 5, 34, 0, 0, 380, 384, 1, 0, 0, 0, 381, 383,
		9, 0, 0, 0, 382, 381, 1, 0, 0, 0, 383, 386, 1, 0, 0, 0, 384, 385, 1, 0,
		0, 0, 384, 382, 1, 0, 0, 0, 385, 387, 1, 0, 0, 0, 386, 384, 1, 0, 0, 0,
		387, 388, 5, 34, 0, 0, 388, 389, 5, 34, 0, 0, 389, 390, 5, 34, 0, 0, 390,
		407, 1, 0, 0, 0, 391, 392, 3, 67, 33, 0, 392, 393, 5, 39, 0, 0, 393, 394,
		5, 39, 0, 0, 394, 395, 5, 39, 0, 0, 395, 399, 1, 0, 0, 0, 396, 398, 9,
		0, 0, 0, 397, 396, 1, 0, 0, 0, 398, 401, 1, 0, 0, 0, 399, 400, 1, 0, 0,
		0, 399, 397, 1, 0, 0, 0, 400, 402, 1, 0, 0, 0, 401, 399, 1, 0, 0, 0, 402,
		403, 5, 39, 0, 0, 403, 404, 5, 39, 0, 0, 404, 405, 5, 39, 0, 0, 405, 407,
		1, 0, 0, 0, 406, 310, 1, 0, 0, 0, 406, 319, 1, 0, 0, 0, 406, 328, 1, 0,
		0, 0, 406, 342, 1, 0, 0, 0, 406, 356, 1, 0, 0, 0, 406, 366, 1, 0, 0, 0,
		406, 376, 1, 0, 0, 0, 406, 391, 1, 0, 0, 0, 407, 90, 1, 0, 0, 0, 408, 409,
		7, 15, 0, 0, 409, 410, 3, 89, 44, 0, 410, 92, 1, 0, 0, 0, 411, 414, 3,
		59, 29, 0, 412, 414, 5, 95, 0, 0, 413, 411, 1, 0, 0, 0, 413, 412, 1, 0,
		0, 0, 414, 420, 1, 0, 0, 0, 415, 419, 3, 59, 29, 0, 416, 419, 3, 61, 30,
		0, 417, 419, 5, 95, 0, 0, 418, 415, 1, 0, 0, 0, 418, 416, 1, 0, 0, 0, 418,
		417, 1, 0, 0, 0, 419, 422, 1, 0, 0, 0, 420, 418, 1, 0, 0, 0, 420, 421,
		1, 0, 0, 0, 421, 94, 1, 0, 0, 0, 422, 420, 1, 0, 0, 0, 36, 0, 176, 181,
		191, 224, 229, 239, 247, 253, 256, 261, 269, 272, 274, 279, 287, 289, 294,
		304, 308, 313, 315, 322, 324, 334, 336, 348, 350, 361, 371, 384, 399, 406,
		413, 418, 420, 1, 0, 1, 0,
	}
	deserializer := antlr.NewATNDeserializer(nil)
	staticData.atn = deserializer.Deserialize(staticData.serializedATN)
	atn := staticData.atn
	staticData.decisionToDFA = make([]*antlr.DFA, len(atn.DecisionToState))
	decisionToDFA := staticData.decisionToDFA
	for index, state := range atn.DecisionToState {
		decisionToDFA[index] = antlr.NewDFA(state, index)
	}
}

// CELLexerInit initializes any static state used to implement CELLexer. By default the
// static state used to implement the lexer is lazily initialized during the first call to
// NewCELLexer(). You can call this function if you wish to initialize the static state ahead
// of time.
func CELLexerInit() {
	staticData := &CELLexerLexerStaticData
	staticData.once.Do(cellexerLexerInit)
}

// NewCELLexer produces a new lexer instance for the optional input antlr.CharStream.
func NewCELLexer(input antlr.CharStream) *CELLexer {
	CELLexerInit()
	l := new(CELLexer)
	l.BaseLexer = antlr.NewBaseLexer(input)
	staticData := &CELLexerLexerStaticData
	l.Interpreter = antlr.NewLexerATNSimulator(l, staticData.atn, staticData.decisionToDFA, staticData.PredictionContextCache)
	l.channelNames = staticData.ChannelNames
	l.modeNames = staticData.ModeNames
	l.RuleNames = staticData.RuleNames
	l.LiteralNames = staticData.LiteralNames
	l.SymbolicNames = staticData.SymbolicNames
	l.GrammarFileName = "CEL.g4"
	// TODO: l.EOF = antlr.TokenEOF

	return l
}

// CELLexer tokens.
const (
	CELLexerEQUALS         = 1
	CELLexerNOT_EQUALS     = 2
	CELLexerIN             = 3
	CELLexerLESS           = 4
	CELLexerLESS_EQUALS    = 5
	CELLexerGREATER_EQUALS = 6
	CELLexerGREATER        = 7
	CELLexerLOGICAL_AND    = 8
	CELLexerLOGICAL_OR     = 9
	CELLexerLBRACKET       = 10
	CELLexerRPRACKET       = 11
	CELLexerLBRACE         = 12
	CELLexerRBRACE         = 13
	CELLexerLPAREN         = 14
	CELLexerRPAREN         = 15
	CELLexerDOT            = 16
	CELLexerCOMMA          = 17
	CELLexerMINUS          = 18
	CELLexerEXCLAM         = 19
	CELLexerQUESTIONMARK   = 20
	CELLexerCOLON          = 21
	CELLexerPLUS           = 22
	CELLexerSTAR           = 23
	CELLexerSLASH          = 24
	CELLexerPERCENT        = 25
	CELLexerCEL_TRUE       = 26
	CELLexerCEL_FALSE      = 27
	CELLexerNUL            = 28
	CELLexerWHITESPACE     = 29
	CELLexerCOMMENT        = 30
	CELLexerNUM_FLOAT      = 31
	CELLexerNUM_INT        = 32
	CELLexerNUM_UINT       = 33
	CELLexerSTRING         = 34
	CELLexerBYTES          = 35
	CELLexerIDENTIFIER     = 36
)
